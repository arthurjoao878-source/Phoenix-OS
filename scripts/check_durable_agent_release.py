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
    "tests/test_durable_agent_migration_guidance.py",
    "tests/test_durable_agent_adrs.py",
    "tests/test_durable_agent_security_review.py",
    "tests/test_durable_agent_release_gate.py",
    "tests/test_v028_release.py",
)

_REQUIRED_SDIST_DOCUMENTS = (
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "pyproject.toml",
    "docs/releases/v0.28.0.md",
    "docs/rfcs/RFC-0028-durable-agent-runs-and-controlled-resumption.md",
    "docs/migrations/v0.27.0-to-v0.28.0-durable-agent.md",
    "docs/security/RFC-0028-durable-agent-threat-model-review.md",
    "docs/adrs/README.md",
    "docs/adrs/ADR-0021-untrusted-canonical-chained-durable-checkpoints.md",
    "docs/adrs/ADR-0022-fenced-leases-and-conditional-durable-mutation.md",
    "docs/adrs/ADR-0023-controlled-recovery-and-explicit-indeterminate-reconciliation.md",
    "docs/adrs/ADR-0024-opt-in-protected-payloads-and-content-free-durable-operations.md",
    "docs/adrs/ADR-0025-opt-in-runtime-owned-durable-lifecycle-retention-and-administration.md",
)

_REQUIRED_INTEGRATION_FILES = (
    "phoenix_os/agent/__init__.py",
    "phoenix_os/configuration/dependencies.py",
    "phoenix_os/inference/__init__.py",
    "phoenix_os/policy/__init__.py",
)

_FORBIDDEN_ARCHIVE_COMPONENTS = frozenset({".env", ".git", "__pycache__"})
_FORBIDDEN_ARCHIVE_SUFFIXES = frozenset({".key", ".p12", ".pem", ".pfx", ".pyc", ".pyo"})


def _run(
    command: Sequence[str],
    *,
    cwd: Path = _ROOT,
    env: Mapping[str, str] | None = None,
) -> None:
    rendered = " ".join(command)
    print(f"+ {rendered}", flush=True)
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


def _durable_test_files() -> tuple[str, ...]:
    discovered = tuple(
        path.relative_to(_ROOT).as_posix()
        for path in sorted((_ROOT / "tests").glob("test_agent_durable_*.py"))
    )
    if not discovered:
        raise RuntimeError("durable-agent regression suite is empty")
    for relative in _COMPANION_TESTS:
        if not (_ROOT / relative).is_file():
            raise RuntimeError(f"required durable-agent release test is missing: {relative}")
    return (*discovered, *_COMPANION_TESTS)


def _durable_source_files() -> tuple[str, ...]:
    source = _ROOT / "src" / "phoenix_os" / "agent"
    files = tuple(f"phoenix_os/agent/{path.name}" for path in sorted(source.glob("durable_*.py")))
    if not files:
        raise RuntimeError("durable-agent package contains no durable modules")
    return files


def _required_package_files() -> frozenset[str]:
    return frozenset(
        {
            "phoenix_os/__init__.py",
            "phoenix_os/py.typed",
            *_durable_source_files(),
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
                f"wheel {wheel.name} is missing required durable-agent files: " + ", ".join(missing)
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
            f"sdist {sdist.name} is missing required durable-agent files: " + ", ".join(missing)
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
from datetime import UTC, datetime, timedelta
from importlib.metadata import version as distribution_version
from pathlib import Path
import sys
from uuid import UUID

import phoenix_os
from phoenix_os.agent import (
    AGENT_RECONCILE_ACTION,
    AGENT_RESUME_ACTION,
    AgentId,
    AgentRunId,
    AgentStepId,
    CanonicalCheckpointCodec,
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointId,
    CheckpointMetadata,
    CheckpointNextOperation,
    CheckpointPayloadProfile,
    CheckpointSchemaVersion,
    CheckpointSequence,
    CompatibilityDigests,
    DurableAgentRunId,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttemptId,
    InMemoryDurableRunStore,
    durable_agent_run_resource,
    durable_reconciliation_resource,
    seal_checkpoint_envelope,
)
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.state import AgentBudgetSnapshot


def digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def budget(now: datetime, *, steps: int) -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=steps,
        model_turns=steps,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=0,
        output_tokens=0,
        started_at=now,
        deadline=now + timedelta(hours=1),
    )


def checkpoint(
    *,
    now: datetime,
    run_id: DurableAgentRunId,
    agent_run_id: AgentRunId,
    step_id: AgentStepId,
    sequence: int,
    previous_digest: CheckpointDigest | None,
    created_at: datetime,
) -> CheckpointEnvelope:
    metadata = CheckpointMetadata(
        agent_id=AgentId("release-durable-agent"),
        actor_id="release-worker",
        next_operation=CheckpointNextOperation.MODEL_TURN,
        budget=budget(now, steps=sequence - 1),
        compatibility=CompatibilityDigests(
            configuration=digest("a"),
            tool_registry=digest("b"),
            model_provider=digest("c"),
            checkpoint_codec=digest("d"),
        ),
        payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
        retention_deadline=now + timedelta(days=1),
        metadata={{"release": "offline-smoke"}},
    )
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=run_id,
            checkpoint_id=CheckpointId(UUID(int=sequence * 100 + 1)),
            sequence=CheckpointSequence(sequence),
            previous_digest=previous_digest,
            run_version=DurableRunVersion(sequence),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=agent_run_id,
            step_id=step_id,
            metadata=metadata,
            created_at=created_at,
            digest=digest("0"),
        )
    )


async def main() -> None:
    assert distribution_version("phoenix-os") == {version!r}
    assert Path(phoenix_os.__file__).resolve().is_relative_to(
        Path(sys.prefix).resolve()
    )

    now = datetime(2026, 8, 10, 16, tzinfo=UTC)
    run_id = DurableAgentRunId(
        UUID("10000000-0000-0000-0000-000000000028")
    )
    agent_run_id = AgentRunId(
        UUID("20000000-0000-0000-0000-000000000028")
    )
    step_id = AgentStepId(
        UUID("30000000-0000-0000-0000-000000000028")
    )
    attempt_id = ExecutionAttemptId(
        UUID("40000000-0000-0000-0000-000000000028")
    )

    first = checkpoint(
        now=now,
        run_id=run_id,
        agent_run_id=agent_run_id,
        step_id=step_id,
        sequence=1,
        previous_digest=None,
        created_at=now + timedelta(seconds=1),
    )

    codec = CanonicalCheckpointCodec()
    encoded = codec.encode(first)
    assert codec.decode(encoded) == first
    assert first.metadata.payload_profile is CheckpointPayloadProfile.METADATA_ONLY
    assert first.metadata.payload_reference is None

    store = InMemoryDurableRunStore()
    await store.create(first)

    stale = await store.lease_manager.acquire(
        run_id,
        owner_id="release-worker-a",
        now=now + timedelta(seconds=2),
    )
    current = await store.lease_manager.acquire(
        run_id,
        owner_id="release-worker-b",
        now=stale.expires_at,
    )
    assert current.generation > stale.generation

    second = checkpoint(
        now=now,
        run_id=run_id,
        agent_run_id=agent_run_id,
        step_id=step_id,
        sequence=2,
        previous_digest=first.digest,
        created_at=current.acquired_at,
    )

    stale_rejected = False
    try:
        await store.append(
            second,
            expected_version=first.run_version,
            lease=stale,
            now=current.acquired_at,
        )
    except AgentStateConflictError:
        stale_rejected = True
    assert stale_rejected

    written = await store.append(
        second,
        expected_version=first.run_version,
        lease=current,
        now=current.acquired_at,
    )
    assert written == second
    assert await store.get_current(run_id) == second
    assert await store.list_history(run_id, limit=2) == (first, second)

    assert AGENT_RESUME_ACTION == "agent.resume"
    assert AGENT_RECONCILE_ACTION == "agent.reconcile"
    assert durable_agent_run_resource(run_id) == f"durable-agent-run:{{run_id}}"
    assert durable_reconciliation_resource(run_id, attempt_id) == (
        f"durable-agent-run:{{run_id}}/attempt:{{attempt_id}}"
    )

    await store.close()
    assert store.closed


asyncio.run(main())
"""
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONNOUSERSITE"] = "1"
    _run(
        (str(python), "-I", "-c", program),
        cwd=smoke_directory,
        env=env,
    )


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
        "Running RFC-0028 durable-agent checkpoint, fencing, recovery, "
        "authorization, reconciliation, protected-payload, retention, "
        "administration, Runtime, migration, ADR, and security suites.",
        flush=True,
    )
    _run((sys.executable, "-m", "pytest", "-q", *_durable_test_files()))

    with tempfile.TemporaryDirectory(prefix="phoenix-durable-agent-release-") as temporary:
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
            cwd=source,
        )
        rebuilt_wheel = _single_artifact(
            rebuilt,
            "*.whl",
            label="wheel rebuilt from sdist",
        )
        _validate_filename_version(rebuilt_wheel, version=version)
        _validate_wheel(
            rebuilt_wheel,
            project_name=project_name,
            version=version,
            requires_python=requires_python,
        )

        print(
            "Installing durable-agent artifacts into isolated offline environments.",
            flush=True,
        )
        _smoke_install(
            wheel,
            version=version,
            workspace=workspace,
            label="wheel",
        )
        _smoke_install(
            rebuilt_wheel,
            version=version,
            workspace=workspace,
            label="sdist-wheel",
        )

    print("RFC-0028 durable-agent release gate passed.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
