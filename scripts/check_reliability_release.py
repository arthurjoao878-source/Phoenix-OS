from __future__ import annotations

import ast
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
from dataclasses import fields
from email.parser import BytesParser
from email.policy import default
from inspect import signature
from pathlib import Path, PurePosixPath

_ROOT = Path(__file__).resolve().parents[1]
_GATE_COMMAND = "python scripts/check_reliability_release.py"
_PREVIOUS_GATE_COMMAND = "python scripts/check_integrated_agent_release.py"
_COMPANION_TESTS = ("tests/test_v037_release.py",)

_EXPLICIT_TESTS = (
    "tests/test_integrated_agent_durable_live_revalidation.py",
    "tests/test_integrated_agent_durable_reconciliation.py",
    "tests/test_integrated_agent_durable_recovery.py",
    "tests/test_integrated_agent_durable_restore.py",
    "tests/test_integrated_agent_durable_resume_gate.py",
    "tests/test_integrated_agent_execution_control.py",
    "tests/test_rfc0037_reliability_release_gate.py",
)

_REQUIRED_RELIABILITY_TESTS = frozenset(
    {
        "tests/test_agent_durable_administration.py",
        "tests/test_agent_durable_attempts.py",
        "tests/test_agent_durable_cancellation_shutdown.py",
        "tests/test_agent_durable_indeterminate_recovery.py",
        "tests/test_agent_durable_integrity_adversarial.py",
        "tests/test_agent_durable_lease_fencing_adversarial.py",
        "tests/test_agent_durable_mutation.py",
        "tests/test_agent_durable_protected_payload.py",
        "tests/test_agent_durable_reconciliation.py",
        "tests/test_agent_durable_reconciliation_administration.py",
        "tests/test_agent_durable_recovery_concurrency.py",
        "tests/test_agent_durable_reliability.py",
        "tests/test_agent_durable_reliability_matrix.py",
        "tests/test_agent_durable_resume_gate.py",
        "tests/test_agent_durable_retention_sqlite_schema.py",
        "tests/test_agent_durable_retention_worker.py",
        "tests/test_agent_durable_runtime_composition.py",
        "tests/test_agent_durable_sqlite.py",
        "tests/test_agent_durable_worker.py",
        *_EXPLICIT_TESTS,
    }
)

_MATRIX_REQUIREMENT_FILES: dict[str, tuple[str, ...]] = {
    "mutation_outcomes_and_exact_reread": (
        "tests/test_agent_durable_mutation.py",
        "tests/test_agent_durable_integrity_adversarial.py",
    ),
    "checkpoint_corruption_truncation_rollback_substitution": (
        "tests/test_agent_durable_integrity_adversarial.py",
        "tests/test_agent_durable_sqlite.py",
    ),
    "fencing_takeover_and_stale_worker_rejection": (
        "tests/test_agent_durable_lease_fencing_adversarial.py",
    ),
    "concurrent_recoverers_and_authoritative_reread": (
        "tests/test_agent_durable_recovery_concurrency.py",
    ),
    "prepared_started_indeterminate_and_reconciliation": (
        "tests/test_agent_durable_attempts.py",
        "tests/test_agent_durable_indeterminate_recovery.py",
        "tests/test_agent_durable_reconciliation.py",
    ),
    "live_policy_profile_tool_schema_model_changes": (
        "tests/test_agent_durable_resume_gate.py",
        "tests/test_integrated_agent_durable_live_revalidation.py",
        "tests/test_integrated_agent_durable_resume_gate.py",
    ),
    "deadline_budget_and_cancellation_continuity": (
        "tests/test_agent_durable_cancellation_shutdown.py",
        "tests/test_agent_durable_reliability_matrix.py",
        "tests/test_integrated_agent_durable_live_revalidation.py",
        "tests/test_integrated_agent_execution_control.py",
    ),
    "retention_cleanup_tombstone_and_restore_freshness": (
        "tests/test_agent_durable_administration.py",
        "tests/test_agent_durable_reconciliation_administration.py",
        "tests/test_agent_durable_retention_sqlite_schema.py",
        "tests/test_agent_durable_retention_worker.py",
        "tests/test_agent_durable_sqlite.py",
    ),
    "protected_payload_restart_safety": (
        "tests/test_agent_durable_protected_payload.py",
        "tests/test_agent_durable_resume_gate.py",
    ),
    "bounded_repeated_restart_and_recovery_failure": (
        "tests/test_agent_durable_reliability_matrix.py",
        "tests/test_agent_durable_worker.py",
        "tests/test_agent_durable_sqlite.py",
    ),
    "content_free_reliability_administration": ("tests/test_agent_durable_administration.py",),
    "production_fault_injector_absence": (
        "tests/test_agent_durable_reliability.py",
        "tests/test_rfc0037_reliability_release_gate.py",
    ),
    "integrated_rfc0036_recovery_composition": (
        "tests/test_integrated_agent_durable_reconciliation.py",
        "tests/test_integrated_agent_durable_recovery.py",
        "tests/test_integrated_agent_durable_restore.py",
        "tests/test_integrated_agent_durable_resume_gate.py",
    ),
}

_REQUIRED_DOCUMENTS = (
    "docs/rfcs/RFC-0037-durable-runs-recovery-and-reliability.md",
    "docs/migrations/v0.36.0-to-v0.37.0-durable-recovery-reliability.md",
    "docs/releases/v0.37.0.md",
    "docs/security/RFC-0037-durable-recovery-reliability-threat-model-review.md",
)

_REQUIRED_WHEEL_FILES = frozenset(
    {
        "phoenix_os/agent/durable_reliability.py",
        "phoenix_os/agent/durable_reliability_fake.py",
        "phoenix_os/agent/durable_recovery.py",
        "phoenix_os/agent/durable_sqlite.py",
        "phoenix_os/agent/durable_worker.py",
        "phoenix_os/integrated_agent/durable_live_revalidation.py",
    }
)

_EXPECTED_FAULT_POINTS = (
    "checkpoint.before_encode",
    "checkpoint.after_encode",
    "checkpoint.before_store_mutation",
    "checkpoint.after_store_commit_before_ack",
    "checkpoint.after_ack",
    "lease.before_acquire",
    "lease.after_acquire",
    "lease.before_renew",
    "lease.after_renew",
    "recovery.after_candidate_read",
    "recovery.after_lease_acquire",
    "recovery.after_reread",
    "recovery.after_live_revalidation",
    "recovery.before_transition",
    "recovery.after_transition_commit",
    "attempt.after_prepared",
    "attempt.after_started",
    "attempt.after_external_return_before_terminal_record",
    "reconcile.before_mutation",
    "reconcile.after_mutation_commit",
    "retention.before_delete",
    "retention.after_delete_commit",
    "shutdown.after_admission_stop",
)

_FORBIDDEN_ARCHIVE_COMPONENTS = frozenset({".env", ".git", "__pycache__"})
_FORBIDDEN_ARCHIVE_SUFFIXES = frozenset({".key", ".p12", ".pem", ".pfx", ".pyc", ".pyo"})
_FORBIDDEN_OPERATIONAL_FIELD_TOKENS = frozenset(
    {
        "content",
        "prompt",
        "response",
        "argument",
        "result",
        "cookie",
        "credential",
        "secret",
        "payload",
        "exception",
    }
)


def _clean_environment() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONNOUSERSITE"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        env.pop(key, None)
    return env


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
        env=_clean_environment() if env is None else dict(env),
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
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise RuntimeError("pyproject project version is invalid")
    if not isinstance(requires_python, str) or not requires_python:
        raise RuntimeError("pyproject Python requirement is missing")
    return name, version, requires_python


def _reliability_test_files() -> tuple[str, ...]:
    agent_durable = {
        path.relative_to(_ROOT).as_posix()
        for path in (_ROOT / "tests").glob("test_agent_durable_*.py")
    }
    selected = agent_durable | set(_EXPLICIT_TESTS)
    missing = sorted(_REQUIRED_RELIABILITY_TESTS - selected)
    if missing:
        raise RuntimeError(
            "RFC-0037 reliability regression surface is missing reviewed tests: "
            + ", ".join(missing)
        )
    for relative in selected:
        if not (_ROOT / relative).is_file():
            raise RuntimeError(f"RFC-0037 reliability test is missing: {relative}")
    for relative in _COMPANION_TESTS:
        if not (_ROOT / relative).is_file():
            raise RuntimeError(f"required RFC-0037 companion test is missing: {relative}")
    return (*tuple(sorted(selected)), *_COMPANION_TESTS)


def _validate_matrix_manifest() -> None:
    selected = frozenset(_reliability_test_files())
    if not _MATRIX_REQUIREMENT_FILES:
        raise RuntimeError("RFC-0037 reliability matrix manifest is empty")
    for requirement, files in _MATRIX_REQUIREMENT_FILES.items():
        if not requirement or not files:
            raise RuntimeError("RFC-0037 reliability matrix manifest is invalid")
        unknown = sorted(set(files) - selected)
        if unknown:
            raise RuntimeError(
                f"reliability requirement {requirement!r} references unreviewed tests: "
                + ", ".join(unknown)
            )
        for relative in files:
            if not (_ROOT / relative).is_file():
                raise RuntimeError(
                    f"reliability requirement {requirement!r} is missing test: {relative}"
                )


def _validate_global_gate_wiring() -> None:
    for relative in (
        "scripts/check.ps1",
        "scripts/check.sh",
        ".github/workflows/ci.yml",
    ):
        text = (_ROOT / relative).read_text(encoding="utf-8")
        if text.count(_GATE_COMMAND) != 1:
            raise RuntimeError(f"{relative} must invoke the reliability gate exactly once")
        if text.count(_PREVIOUS_GATE_COMMAND) != 1:
            raise RuntimeError(f"{relative} must retain the integrated-agent gate exactly once")
        if text.index(_GATE_COMMAND) < text.index(_PREVIOUS_GATE_COMMAND):
            raise RuntimeError(
                f"{relative} must run the reliability gate after the integrated-agent gate"
            )


def _validate_documents() -> None:
    for relative in _REQUIRED_DOCUMENTS:
        if not (_ROOT / relative).is_file():
            raise RuntimeError(f"required RFC-0037 reliability document is missing: {relative}")

    threat = (
        _ROOT / "docs/security/RFC-0037-durable-recovery-reliability-threat-model-review.md"
    ).read_text(encoding="utf-8")
    invariants = {
        int(value)
        for value in re.findall(
            r"^- Invariant ([0-9]+):",
            threat,
            flags=re.MULTILINE,
        )
    }
    if invariants != set(range(1, 49)):
        raise RuntimeError("RFC-0037 threat review must map exactly invariants 1..48")

    migration = (
        _ROOT / "docs/migrations/v0.36.0-to-v0.37.0-durable-recovery-reliability.md"
    ).read_text(encoding="utf-8")
    for marker in (
        "## Compatibility default",
        "## Durable SQLite migration",
        "## Recovery behavior",
        "## Rollback guidance",
        "## Release-gate adoption",
    ):
        if marker not in migration:
            raise RuntimeError(f"RFC-0037 migration guidance is missing: {marker}")


def _validate_fault_surface() -> None:
    from phoenix_os.agent.composition import AgentRuntimeStack, create_agent_runtime_stack
    from phoenix_os.agent.durable_administration import DurableReliabilityAdministrationView
    from phoenix_os.agent.durable_reliability import (
        NOOP_RELIABILITY_FAULT_INJECTOR,
        ReliabilityFaultPoint,
    )
    from phoenix_os.agent.durable_runtime import (
        DurableAgentRuntimeStack,
        create_durable_agent_runtime_stack,
    )

    if tuple(point.value for point in ReliabilityFaultPoint) != _EXPECTED_FAULT_POINTS:
        raise RuntimeError("RFC-0037 fault-point vocabulary drifted")

    NOOP_RELIABILITY_FAULT_INJECTOR.inject(ReliabilityFaultPoint.CHECKPOINT_BEFORE_ENCODE)

    for factory in (create_agent_runtime_stack, create_durable_agent_runtime_stack):
        parameters = signature(factory).parameters
        if "fault_injector" in parameters or "reliability_fault_injector" in parameters:
            raise RuntimeError("ordinary production composition exposes a fault injector")

    for stack_type in (AgentRuntimeStack, DurableAgentRuntimeStack):
        names = {field.name for field in fields(stack_type)}
        if "fault_injector" in names or "reliability_fault_injector" in names:
            raise RuntimeError("ordinary runtime stack stores a fault injector")

    reliability_fields = tuple(field.name for field in fields(DurableReliabilityAdministrationView))
    for name in reliability_fields:
        if any(token in name for token in _FORBIDDEN_OPERATIONAL_FIELD_TOKENS):
            raise RuntimeError(f"reliability administration exposes content-shaped field: {name}")

    source_root = _ROOT / "src" / "phoenix_os"
    fake_module = source_root / "agent" / "durable_reliability_fake.py"
    for path in sorted(source_root.rglob("*.py")):
        if path == fake_module:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == (
                "phoenix_os.agent.durable_reliability_fake"
            ):
                raise RuntimeError(f"production source imports test-only reliability fake: {path}")
            if isinstance(node, ast.Import):
                if any(
                    alias.name == "phoenix_os.agent.durable_reliability_fake"
                    for alias in node.names
                ):
                    raise RuntimeError(
                        f"production source imports test-only reliability fake: {path}"
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
        missing = sorted(_REQUIRED_WHEEL_FILES - available)
        if missing:
            raise RuntimeError(
                f"wheel {wheel.name} is missing RFC-0037 modules: " + ", ".join(missing)
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
        if any(name.startswith("tests/") or name.startswith("docs/") for name in names):
            raise RuntimeError("wheel unexpectedly contains tests or repository documentation")


def _sdist_relative_names(sdist: Path) -> frozenset[str]:
    with tarfile.open(sdist, mode="r:gz") as archive:
        names = tuple(member.name for member in archive.getmembers())
        _validate_archive_names(names, label=f"sdist {sdist.name}")
        roots = {PurePosixPath(name).parts[0] for name in names if PurePosixPath(name).parts}
        if len(roots) != 1:
            raise RuntimeError("sdist must contain exactly one top-level directory")
        root = next(iter(roots))
        prefix = f"{root}/"
        return frozenset(
            name[len(prefix) :] for name in names if name.startswith(prefix) and name != prefix
        )


def _validate_sdist(sdist: Path) -> None:
    relative = _sdist_relative_names(sdist)
    required = {
        "README.md",
        "LICENSE",
        "pyproject.toml",
        "scripts/check_reliability_release.py",
        *_REQUIRED_DOCUMENTS,
        *{f"src/{name}" for name in _REQUIRED_WHEEL_FILES},
    }
    missing = sorted(required - relative)
    if missing:
        raise RuntimeError(
            f"sdist {sdist.name} is missing RFC-0037 release evidence: " + ", ".join(missing)
        )


def _extract_sdist(sdist: Path, destination: Path) -> Path:
    with tarfile.open(sdist, mode="r:gz") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk():
                raise RuntimeError(f"sdist contains unsafe entry: {member.name}")
        archive.extractall(destination, filter="data")
    roots = [path for path in destination.iterdir() if path.is_dir()]
    if len(roots) != 1:
        raise RuntimeError("extracted sdist must contain one source directory")
    return roots[0]


def _single_artifact(directory: Path, pattern: str, *, label: str) -> Path:
    matches = tuple(directory.glob(pattern))
    if len(matches) != 1:
        rendered = ", ".join(path.name for path in matches) or "<none>"
        raise RuntimeError(f"expected one {label}; found {len(matches)}: {rendered}")
    return matches[0]


def _venv_python(environment: Path) -> Path:
    return environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


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

    smoke = workspace / f"smoke-{label}"
    smoke.mkdir()
    program = f"""
from dataclasses import fields
from importlib.metadata import version as distribution_version
from inspect import signature
from pathlib import Path
import sys

import phoenix_os
from phoenix_os.agent.composition import AgentRuntimeStack, create_agent_runtime_stack
from phoenix_os.agent.durable_reliability import (
    NOOP_RELIABILITY_FAULT_INJECTOR,
    ReliabilityFaultPoint,
)
from phoenix_os.agent.durable_runtime import (
    DurableAgentRuntimeStack,
    create_durable_agent_runtime_stack,
)

assert distribution_version("phoenix-os") == {version!r}
assert Path(phoenix_os.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())

for factory in (create_agent_runtime_stack, create_durable_agent_runtime_stack):
    parameters = signature(factory).parameters
    assert "fault_injector" not in parameters
    assert "reliability_fault_injector" not in parameters

for stack_type in (AgentRuntimeStack, DurableAgentRuntimeStack):
    names = {{field.name for field in fields(stack_type)}}
    assert "fault_injector" not in names
    assert "reliability_fault_injector" not in names

NOOP_RELIABILITY_FAULT_INJECTOR.inject(
    ReliabilityFaultPoint.RECOVERY_AFTER_LIVE_REVALIDATION
)
print("RFC-0037 isolated reliability smoke passed")
"""
    _run((str(python), "-I", "-c", program), cwd=smoke)


def main() -> int:
    project_name, version, requires_python = _project_metadata()
    _validate_matrix_manifest()
    _validate_global_gate_wiring()
    _validate_documents()
    _validate_fault_surface()

    tests = _reliability_test_files()
    print(
        f"Running RFC-0037 deterministic reliability surface ({len(tests)} files).",
        flush=True,
    )
    _run((sys.executable, "-m", "pytest", "-q", *tests))

    with tempfile.TemporaryDirectory(prefix="phoenix-rfc0037-reliability-") as temporary:
        workspace = Path(temporary)
        artifacts = workspace / "dist"
        artifacts.mkdir()

        print("Building RFC-0037 wheel and sdist without network isolation.", flush=True)
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

        print("Rebuilding RFC-0037 wheel from validated sdist.", flush=True)
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
        _validate_wheel(
            rebuilt_wheel,
            project_name=project_name,
            version=version,
            requires_python=requires_python,
        )

        print("Running isolated offline RFC-0037 artifact smoke.", flush=True)
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

    print("RFC-0037 reliability release gate passed.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
