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
from pathlib import Path, PurePosixPath

_ROOT = Path(__file__).resolve().parents[1]
_GATE_COMMAND = "python scripts/check_integrated_agent_release.py"
_COMPANION_TESTS = ("tests/test_v036_release.py",)

_REQUIRED_INTEGRATED_MODULES = frozenset(
    {
        "phoenix_os/integrated_agent/__init__.py",
        "phoenix_os/integrated_agent/administration.py",
        "phoenix_os/integrated_agent/admission.py",
        "phoenix_os/integrated_agent/codec.py",
        "phoenix_os/integrated_agent/composition.py",
        "phoenix_os/integrated_agent/configuration.py",
        "phoenix_os/integrated_agent/contracts.py",
        "phoenix_os/integrated_agent/data_flow.py",
        "phoenix_os/integrated_agent/durable_context_resupply.py",
        "phoenix_os/integrated_agent/durable_live_revalidation.py",
        "phoenix_os/integrated_agent/durable_projection.py",
        "phoenix_os/integrated_agent/durable_recovery.py",
        "phoenix_os/integrated_agent/durable_root.py",
        "phoenix_os/integrated_agent/durable_transitions.py",
        "phoenix_os/integrated_agent/errors.py",
        "phoenix_os/integrated_agent/execution_control.py",
        "phoenix_os/integrated_agent/execution_guard.py",
        "phoenix_os/integrated_agent/observer.py",
        "phoenix_os/integrated_agent/planning.py",
        "phoenix_os/integrated_agent/profiles.py",
        "phoenix_os/integrated_agent/runtime.py",
    }
)

_REQUIRED_INTEGRATION_FILES = frozenset(
    {
        "phoenix_os/__init__.py",
        "phoenix_os/py.typed",
        "phoenix_os/agent/admission.py",
        "phoenix_os/agent/authorization.py",
        "phoenix_os/agent/contracts.py",
        "phoenix_os/agent/loop.py",
        "phoenix_os/agent/registry.py",
        "phoenix_os/agent/service.py",
        "phoenix_os/agent/state.py",
        "phoenix_os/agent/tools.py",
        "phoenix_os/authority/catalog.py",
        "phoenix_os/runtime/__init__.py",
    }
)

_REQUIRED_INTEGRATED_TESTS = frozenset(
    {
        "tests/test_integrated_agent_administration.py",
        "tests/test_integrated_agent_administration_adversarial.py",
        "tests/test_integrated_agent_admission.py",
        "tests/test_integrated_agent_codec.py",
        "tests/test_integrated_agent_composition.py",
        "tests/test_integrated_agent_configuration.py",
        "tests/test_integrated_agent_contracts.py",
        "tests/test_integrated_agent_data_flow.py",
        "tests/test_integrated_agent_downstream_bridges.py",
        "tests/test_integrated_agent_durable_context_resupply.py",
        "tests/test_integrated_agent_durable_live_projection.py",
        "tests/test_integrated_agent_durable_live_revalidation.py",
        "tests/test_integrated_agent_durable_projection.py",
        "tests/test_integrated_agent_durable_reconciliation.py",
        "tests/test_integrated_agent_durable_recovery.py",
        "tests/test_integrated_agent_durable_restore.py",
        "tests/test_integrated_agent_durable_resume_gate.py",
        "tests/test_integrated_agent_durable_root.py",
        "tests/test_integrated_agent_durable_transitions.py",
        "tests/test_integrated_agent_end_to_end.py",
        "tests/test_integrated_agent_execution_control.py",
        "tests/test_integrated_agent_execution_guard.py",
        "tests/test_integrated_agent_memory_host_final_admission.py",
        "tests/test_integrated_agent_observability_adversarial.py",
        "tests/test_integrated_agent_observer.py",
        "tests/test_integrated_agent_planning.py",
        "tests/test_integrated_agent_profiles.py",
        "tests/test_integrated_agent_release_gate.py",
        "tests/test_integrated_agent_runtime.py",
        "tests/test_integrated_agent_security_adversarial.py",
    }
)

_REQUIRED_HARDENING_FILES = (
    "docs/rfcs/RFC-0036-secure-integrated-agent-execution-and-end-to-end-orchestration.md",
    "docs/migrations/v0.35.0-to-v0.36.0-secure-integrated-agent-execution.md",
    "docs/releases/v0.36.0.md",
    "docs/security/RFC-0036-secure-integrated-agent-execution-threat-model-review.md",
    "docs/adrs/README.md",
    "docs/adrs/ADR-0068-plans-and-integrated-content-are-data.md",
    "docs/adrs/ADR-0069-server-owned-integrated-profiles-and-exact-capability-bridges.md",
    "docs/adrs/ADR-0070-exact-provenance-cross-subsystem-flow-and-final-disclosure.md",
    "docs/adrs/ADR-0071-sequential-integrated-effects-and-no-transparent-retry.md",
    "docs/adrs/ADR-0072-metadata-only-recovery-and-content-free-operations.md",
)

_REQUIRED_SDIST_DOCUMENTS = (
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "pyproject.toml",
    *_REQUIRED_HARDENING_FILES,
)

_SECURITY_REQUIREMENT_FILES: dict[str, tuple[str, ...]] = {
    "immutable_task_digest_binding": (
        "tests/test_integrated_agent_contracts.py",
        "tests/test_integrated_agent_admission.py",
    ),
    "agent_run_intent_profile_freshness_binding": (
        "tests/test_integrated_agent_admission.py",
        "tests/test_integrated_agent_configuration.py",
    ),
    "reuse_rfc0027_run_and_step_ids": (
        "tests/test_integrated_agent_runtime.py",
        "tests/test_integrated_agent_execution_guard.py",
    ),
    "no_task_run_substitution": (
        "tests/test_integrated_agent_admission.py",
        "tests/test_integrated_agent_release_gate.py",
    ),
    "no_second_capability_registry": (
        "tests/test_integrated_agent_composition.py",
        "tests/test_integrated_agent_runtime.py",
        "tests/test_integrated_agent_release_gate.py",
    ),
    "model_turn_exactly_final_or_tool_proposal": (
        "tests/test_integrated_agent_execution_guard.py",
        "tests/test_integrated_agent_end_to_end.py",
    ),
    "plan_updates_only_reserved_tool_and_tool_invoke": (
        "tests/test_integrated_agent_planning.py",
        "tests/test_integrated_agent_execution_guard.py",
    ),
    "planner_cannot_create_authority": (
        "tests/test_integrated_agent_planning.py",
        "tests/test_integrated_agent_security_adversarial.py",
    ),
    "every_exposed_tool_exact_binding": (
        "tests/test_integrated_agent_composition.py",
        "tests/test_integrated_agent_profiles.py",
    ),
    "bridge_substitution_rejected": (
        "tests/test_integrated_agent_downstream_bridges.py",
        "tests/test_integrated_agent_security_adversarial.py",
    ),
    "data_flow_denied_before_approval_or_effect": (
        "tests/test_integrated_agent_data_flow.py",
        "tests/test_integrated_agent_execution_guard.py",
        "tests/test_integrated_agent_security_adversarial.py",
    ),
    "independent_tool_and_downstream_authority": (
        "tests/test_integrated_agent_downstream_bridges.py",
        "tests/test_integrated_agent_security_adversarial.py",
    ),
    "malicious_planning_fails_closed": (
        "tests/test_integrated_agent_planning.py",
        "tests/test_integrated_agent_security_adversarial.py",
    ),
    "prompt_injection_cannot_manufacture_resources": (
        "tests/test_integrated_agent_security_adversarial.py",
        "tests/test_integrated_agent_memory_host_final_admission.py",
    ),
    "cross_subsystem_exfiltration_denied_before_effect": (
        "tests/test_integrated_agent_security_adversarial.py",
        "tests/test_integrated_agent_data_flow.py",
    ),
    "final_user_result_audience_and_source_scope": (
        "tests/test_integrated_agent_end_to_end.py",
        "tests/test_integrated_agent_memory_host_final_admission.py",
    ),
    "exact_provenance_atoms": (
        "tests/test_integrated_agent_data_flow.py",
        "tests/test_integrated_agent_execution_guard.py",
    ),
    "conservative_provenance_transformations": (
        "tests/test_integrated_agent_planning.py",
        "tests/test_integrated_agent_downstream_bridges.py",
        "tests/test_integrated_agent_execution_guard.py",
    ),
    "no_provenance_laundering_or_declassification": (
        "tests/test_integrated_agent_data_flow.py",
        "tests/test_integrated_agent_security_adversarial.py",
    ),
    "provenance_overflow_fails_closed": (
        "tests/test_integrated_agent_data_flow.py",
        "tests/test_integrated_agent_execution_guard.py",
    ),
    "budget_deadline_cancellation_races": (
        "tests/test_integrated_agent_execution_control.py",
        "tests/test_integrated_agent_execution_guard.py",
    ),
    "stale_integrated_and_downstream_profiles": (
        "tests/test_integrated_agent_configuration.py",
        "tests/test_integrated_agent_downstream_bridges.py",
        "tests/test_integrated_agent_durable_live_revalidation.py",
    ),
    "workspace_browser_network_composition": (
        "tests/test_integrated_agent_downstream_bridges.py",
        "tests/test_integrated_agent_memory_host_final_admission.py",
    ),
    "no_automatic_retry_possible_effect": (
        "tests/test_integrated_agent_execution_control.py",
        "tests/test_integrated_agent_durable_reconciliation.py",
    ),
    "indeterminate_effect_enters_rfc0028_reconciliation": (
        "tests/test_integrated_agent_durable_reconciliation.py",
        "tests/test_integrated_agent_durable_transitions.py",
    ),
    "recovery_exact_task_profile_and_fresh_auth": (
        "tests/test_integrated_agent_durable_recovery.py",
        "tests/test_integrated_agent_durable_live_revalidation.py",
    ),
    "metadata_only_recovery_cannot_resume_without_context": (
        "tests/test_integrated_agent_durable_restore.py",
        "tests/test_integrated_agent_durable_resume_gate.py",
    ),
    "missing_context_waits_for_resupply_or_fails_safely": (
        "tests/test_integrated_agent_durable_context_resupply.py",
        "tests/test_integrated_agent_durable_resume_gate.py",
    ),
    "consumed_approvals_invalid_after_recovery": (
        "tests/test_integrated_agent_durable_live_revalidation.py",
        "tests/test_integrated_agent_durable_recovery.py",
    ),
    "stale_browser_ids_invalid_after_recovery": (
        "tests/test_integrated_agent_durable_live_revalidation.py",
        "tests/test_integrated_agent_durable_recovery.py",
    ),
    "routine_observability_content_free": (
        "tests/test_integrated_agent_observer.py",
        "tests/test_integrated_agent_observability_adversarial.py",
        "tests/test_integrated_agent_runtime.py",
    ),
    "separate_redacted_inspection_authority": (
        "tests/test_integrated_agent_administration.py",
        "tests/test_integrated_agent_administration_adversarial.py",
    ),
    "wheel_and_sdist_package_boundary": ("tests/test_integrated_agent_release_gate.py",),
    "isolated_install_and_smoke": ("tests/test_integrated_agent_release_gate.py",),
    "deterministic_network_free_end_to_end": (
        "tests/test_integrated_agent_end_to_end.py",
        "tests/test_integrated_agent_security_adversarial.py",
    ),
    "observer_best_effort_outside_execution_path": (
        "tests/test_integrated_agent_runtime.py",
        "tests/test_integrated_agent_observability_adversarial.py",
    ),
}

_FORBIDDEN_ARCHIVE_COMPONENTS = frozenset({".env", ".git", "__pycache__"})
_FORBIDDEN_ARCHIVE_SUFFIXES = frozenset({".key", ".p12", ".pem", ".pfx", ".pyc", ".pyo"})
_VERSION_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+){2}$")

_OBSERVATION_FIELDS = (
    "task_id",
    "run_id",
    "phase",
    "profile_id",
    "profile_generation",
    "step_id",
    "plan_revision",
    "capability_id",
    "tool_id",
    "action_category",
    "effect_disposition",
    "failure_class",
    "budget_usage",
    "duration_ms",
    "waiting_reason",
    "schema_version",
)
_ADMIN_SNAPSHOT_FIELDS = (
    "runtime_state",
    "profile_id",
    "profile_generation",
    "admission_closed",
    "planner_configured",
    "planner_closed",
    "execution_guard_configured",
    "execution_guard_closed",
    "composition_configured",
    "schema_version",
)
_REDACTED_INSPECTION_FIELDS = (
    "task_id",
    "run_id",
    "profile_id",
    "profile_generation",
    "plan_revision",
    "budget_usage",
    "failure_class",
    "provenance_source_kinds",
    "schema_version",
)
_FORBIDDEN_OPERATIONAL_FIELD_TOKENS = frozenset(
    {
        "content",
        "prompt",
        "message",
        "response",
        "argument",
        "result",
        "cookie",
        "credential",
        "secret",
        "approval",
        "exception",
        "policy",
        "source_binding",
        "freshness",
        "metadata",
        "payload",
        "details",
    }
)


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
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    if not isinstance(project, dict):
        raise RuntimeError("pyproject project metadata is invalid")
    name = project.get("name")
    version = project.get("version")
    requires_python = project.get("requires-python")
    if (
        not isinstance(name, str)
        or not name
        or not isinstance(version, str)
        or not version
        or not isinstance(requires_python, str)
        or not requires_python
    ):
        raise RuntimeError("pyproject release metadata is incomplete")
    return name, version, requires_python


def _integrated_test_files() -> tuple[str, ...]:
    discovered = tuple(
        path.relative_to(_ROOT).as_posix()
        for path in sorted((_ROOT / "tests").glob("test_integrated_agent_*.py"))
    )
    available = frozenset(discovered)
    missing = sorted(_REQUIRED_INTEGRATED_TESTS - available)
    if missing:
        raise RuntimeError(
            "integrated-agent regression suite is missing required tests: " + ", ".join(missing)
        )
    for relative in _COMPANION_TESTS:
        if not (_ROOT / relative).is_file():
            raise RuntimeError(f"required integrated-agent companion test is missing: {relative}")
    return (*discovered, *_COMPANION_TESTS)


def _integrated_source_files() -> tuple[str, ...]:
    source = _ROOT / "src" / "phoenix_os" / "integrated_agent"
    discovered = tuple(
        f"phoenix_os/integrated_agent/{path.relative_to(source).as_posix()}"
        for path in sorted(source.rglob("*.py"))
    )
    available = frozenset(discovered)
    missing = sorted(_REQUIRED_INTEGRATED_MODULES - available)
    unexpected = sorted(available - _REQUIRED_INTEGRATED_MODULES)
    if missing:
        raise RuntimeError(
            "integrated-agent package is missing reviewed modules: " + ", ".join(missing)
        )
    if unexpected:
        raise RuntimeError(
            "integrated-agent package contains unreviewed modules: " + ", ".join(unexpected)
        )
    return discovered


def _required_package_files() -> frozenset[str]:
    return frozenset(
        {
            *_REQUIRED_INTEGRATED_MODULES,
            *_REQUIRED_INTEGRATION_FILES,
        }
    )


def _validate_security_manifest() -> None:
    if not _SECURITY_REQUIREMENT_FILES:
        raise RuntimeError("integrated-agent security requirement manifest is empty")
    known = _REQUIRED_INTEGRATED_TESTS
    for requirement, paths in _SECURITY_REQUIREMENT_FILES.items():
        if not requirement or not paths:
            raise RuntimeError("integrated-agent security requirement mapping is invalid")
        unknown = sorted(set(paths) - known)
        if unknown:
            raise RuntimeError(
                f"security requirement {requirement!r} references unreviewed tests: "
                + ", ".join(unknown)
            )
        for relative in paths:
            if not (_ROOT / relative).is_file():
                raise RuntimeError(
                    f"security requirement {requirement!r} is missing test: {relative}"
                )


def _validate_global_gate_wiring() -> None:
    browser_command = "python scripts/check_browser_automation_release.py"
    for relative in (
        "scripts/check.ps1",
        "scripts/check.sh",
        ".github/workflows/ci.yml",
    ):
        text = (_ROOT / relative).read_text(encoding="utf-8")
        if text.count(_GATE_COMMAND) != 1:
            raise RuntimeError(
                f"{relative} must invoke the integrated-agent release gate exactly once"
            )
        if browser_command not in text:
            raise RuntimeError(f"{relative} is missing the browser release gate")
        if text.index(_GATE_COMMAND) < text.index(browser_command):
            raise RuntimeError(
                f"{relative} must run integrated-agent release after browser release"
            )


def _validate_source_invariants() -> None:
    source_root = _ROOT / "src" / "phoenix_os" / "integrated_agent"
    for path in sorted(source_root.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text, filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value == "task.run"
            ):
                raise RuntimeError(
                    f"integrated source contains forbidden task.run authority literal: {path}"
                )
            if isinstance(node, ast.ClassDef) and node.name == "ToolRegistry":
                raise RuntimeError(f"integrated source defines a second ToolRegistry: {path}")
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "ToolRegistry" and node.module != "phoenix_os.agent.registry":
                        raise RuntimeError(
                            f"integrated source imports non-canonical ToolRegistry: {path}"
                        )

    runtime_text = (source_root / "runtime.py").read_text(encoding="utf-8")
    for marker in (
        "IntegratedAgentObserver",
        "NullIntegratedAgentObserver",
        "_record_observation",
        "_drain_observers",
    ):
        if marker not in runtime_text:
            raise RuntimeError(f"integrated runtime observer wiring is missing: {marker}")
    if "await self._observer.record" in runtime_text:
        raise RuntimeError(
            "integrated runtime must not await observer.record on the execution path"
        )


def _validate_operational_shapes() -> None:
    from phoenix_os.integrated_agent.administration import (
        IntegratedAgentAdministrationSnapshot,
        IntegratedAgentRedactedRunInspection,
    )
    from phoenix_os.integrated_agent.observer import IntegratedAgentObservation

    observed = tuple(field.name for field in fields(IntegratedAgentObservation))
    snapshot = tuple(field.name for field in fields(IntegratedAgentAdministrationSnapshot))
    inspection = tuple(field.name for field in fields(IntegratedAgentRedactedRunInspection))
    if observed != _OBSERVATION_FIELDS:
        raise RuntimeError("integrated observation field boundary drifted")
    if snapshot != _ADMIN_SNAPSHOT_FIELDS:
        raise RuntimeError("integrated administration snapshot field boundary drifted")
    if inspection != _REDACTED_INSPECTION_FIELDS:
        raise RuntimeError("integrated redacted inspection field boundary drifted")

    for label, names in (
        ("observation", observed),
        ("administration snapshot", snapshot),
        ("redacted inspection", inspection),
    ):
        for name in names:
            if any(token in name for token in _FORBIDDEN_OPERATIONAL_FIELD_TOKENS):
                raise RuntimeError(f"{label} exposes forbidden content-shaped field: {name}")


def _validate_threat_review() -> None:
    path = _ROOT / "docs/security/RFC-0036-secure-integrated-agent-execution-threat-model-review.md"
    text = path.read_text(encoding="utf-8")
    invariants = {
        int(value)
        for value in re.findall(
            r"^- Invariant ([0-9]+):",
            text,
            flags=re.MULTILINE,
        )
    }
    if invariants != set(range(1, 103)):
        raise RuntimeError("RFC-0036 threat review must map exactly invariants 1..102")


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


def _validate_exact_integrated_package_files(
    names: Sequence[str],
    *,
    prefix: str,
    label: str,
) -> None:
    root = f"{prefix}phoenix_os/integrated_agent/"
    discovered = frozenset(
        name[len(prefix) :]
        for name in names
        if name.startswith(root) and name != root and not name.endswith("/")
    )
    missing = sorted(_REQUIRED_INTEGRATED_MODULES - discovered)
    unexpected = sorted(discovered - _REQUIRED_INTEGRATED_MODULES)
    if missing:
        raise RuntimeError(
            f"{label} is missing integrated-agent package files: " + ", ".join(missing)
        )
    if unexpected:
        raise RuntimeError(
            f"{label} contains unexpected integrated-agent package files: " + ", ".join(unexpected)
        )


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
        _validate_exact_integrated_package_files(
            names,
            prefix="",
            label=f"wheel {wheel.name}",
        )
        missing = sorted(_required_package_files() - frozenset(names))
        if missing:
            raise RuntimeError(
                f"wheel {wheel.name} is missing required integrated-agent files: "
                + ", ".join(missing)
            )
        metadata_paths = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_paths) != 1:
            raise RuntimeError(f"wheel {wheel.name} must contain exactly one METADATA file")
        metadata = BytesParser(policy=default).parsebytes(archive.read(metadata_paths[0]))
        if (
            metadata["Name"] != project_name
            or metadata["Version"] != version
            or metadata["Requires-Python"] != requires_python
        ):
            raise RuntimeError("wheel metadata does not match pyproject")
        if any(name.startswith("tests/") or name.startswith("docs/") for name in names):
            raise RuntimeError("wheel unexpectedly contains tests or repository documentation")


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
    _validate_exact_integrated_package_files(
        tuple(relative),
        prefix="src/",
        label=f"sdist {sdist.name}",
    )
    required = {
        *_REQUIRED_SDIST_DOCUMENTS,
        *{f"src/{name}" for name in _required_package_files()},
    }
    missing = sorted(required - relative)
    if missing:
        raise RuntimeError(
            f"sdist {sdist.name} is missing required integrated-agent files: " + ", ".join(missing)
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


def _venv_python(environment: Path) -> Path:
    return environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _clean_subprocess_environment() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONNOUSERSITE"] = "1"
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
from pathlib import Path
from uuid import UUID
import sys

import phoenix_os
from phoenix_os.integrated_agent import (
    INTEGRATED_AGENT_HEALTH_READ_PERMISSION,
    INTEGRATED_AGENT_INSPECTION_READ_PERMISSION,
    IntegratedAgentObservation,
    IntegratedAgentRuntime,
    IntegratedTaskId,
    IntegratedTaskRequest,
)

assert distribution_version("phoenix-os") == {version!r}
assert Path(phoenix_os.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
assert INTEGRATED_AGENT_HEALTH_READ_PERMISSION == "integrated.agent.health.read"
assert INTEGRATED_AGENT_INSPECTION_READ_PERMISSION == "integrated.agent.inspection.read"
task = IntegratedTaskRequest(
    task_id=IntegratedTaskId(UUID("12345678-1234-5678-9234-567812345678")),
    objective="isolated integrated-agent release smoke",
)
assert str(task.task_id)
assert IntegratedAgentRuntime is not None
field_names = tuple(field.name for field in fields(IntegratedAgentObservation))
assert "metadata" not in field_names
assert "content" not in field_names
"""
    _run(
        (str(python), "-I", "-c", program),
        cwd=smoke,
        env=_clean_subprocess_environment(),
    )


def _network_free_pytest() -> None:
    program = r"""
import ipaddress
import sys


def _is_local_address(address):
    if not isinstance(address, tuple) or not address:
        return True
    host = address[0]
    if not isinstance(host, str):
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_local_host(host):
    if host is None:
        return True
    if isinstance(host, bytes):
        try:
            host = host.decode("ascii")
        except UnicodeDecodeError:
            return False
    if not isinstance(host, str):
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _deny_external_network(event, args):
    if event == "socket.connect":
        _socket, address = args
        if not _is_local_address(address):
            raise AssertionError(
                f"external network access is forbidden in integrated E2E: {address!r}"
            )
        return

    if event in {
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyname_ex",
    }:
        host = args[0] if args else None
        if not _is_local_host(host):
            raise AssertionError(
                f"external DNS resolution is forbidden in integrated E2E: {host!r}"
            )


sys.addaudithook(_deny_external_network)

import pytest

raise SystemExit(
    pytest.main(
        [
            "-p",
            "no:cacheprovider",
            "-q",
            "tests/test_integrated_agent_end_to_end.py",
            "tests/test_integrated_agent_security_adversarial.py",
        ]
    )
)
"""
    _run(
        (sys.executable, "-c", program),
        env=_clean_subprocess_environment(),
    )


def _release_artifact_names(version: str) -> tuple[str, str]:
    if not isinstance(version, str) or _VERSION_PATTERN.fullmatch(version) is None:
        raise RuntimeError(f"unsupported integrated-agent release version: {version!r}")
    return (
        f"phoenix_os-{version}-py3-none-any.whl",
        f"phoenix_os-{version}.tar.gz",
    )


def _exact_artifacts(
    directory: Path,
    expected_names: Sequence[str],
    *,
    label: str,
) -> tuple[Path, ...]:
    expected_sequence = tuple(expected_names)
    expected = frozenset(expected_sequence)
    if len(expected) != len(expected_sequence):
        raise RuntimeError(f"{label} contains duplicate expected artifact names")
    entries = {path.name: path for path in directory.iterdir()}
    actual = frozenset(entries)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise RuntimeError(
            f"{label} artifact set mismatch: missing={missing}, unexpected={unexpected}"
        )
    artifacts = tuple(entries[name] for name in expected_sequence)
    non_files = sorted(artifact.name for artifact in artifacts if not artifact.is_file())
    if non_files:
        raise RuntimeError(f"{label} contains non-file artifacts: {non_files}")
    return artifacts


def main() -> None:
    project_name, version, requires_python = _project_metadata()
    if project_name != "phoenix-os":
        raise RuntimeError("integrated-agent release gate requires phoenix-os project metadata")

    tests = _integrated_test_files()
    _integrated_source_files()
    _validate_security_manifest()
    _validate_global_gate_wiring()
    _validate_source_invariants()
    _validate_operational_shapes()
    _validate_threat_review()

    for relative in _REQUIRED_HARDENING_FILES:
        if not (_ROOT / relative).is_file():
            raise RuntimeError(f"required integrated-agent hardening file is missing: {relative}")

    _run(
        (
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            *tests,
        )
    )
    _network_free_pytest()

    wheel_name, sdist_name = _release_artifact_names(version)
    with tempfile.TemporaryDirectory(prefix="phoenix-integrated-agent-release-") as temp:
        workspace = Path(temp)
        dist = workspace / "dist"
        dist.mkdir()
        _run(
            (
                sys.executable,
                "-m",
                "build",
                "--sdist",
                "--wheel",
                "--no-isolation",
                "--outdir",
                str(dist),
            )
        )
        wheel, sdist = _exact_artifacts(
            dist,
            (wheel_name, sdist_name),
            label="release build",
        )
        _validate_wheel(
            wheel,
            project_name=project_name,
            version=version,
            requires_python=requires_python,
        )
        _validate_sdist(sdist)
        _smoke_install(
            wheel,
            version=version,
            workspace=workspace,
            label="source-wheel",
        )

        extracted = workspace / "extracted"
        extracted.mkdir()
        source = _extract_sdist(sdist, extracted)
        rebuilt = workspace / "rebuilt"
        rebuilt.mkdir()
        print("Rebuilding a wheel from the validated integrated-agent sdist.", flush=True)
        _run(
            (
                sys.executable,
                "-m",
                "build",
                "--wheel",
                "--no-isolation",
                "--outdir",
                str(rebuilt),
            ),
            cwd=source,
        )
        (rebuilt_wheel,) = _exact_artifacts(
            rebuilt,
            (wheel_name,),
            label="rebuilt wheel",
        )
        _validate_wheel(
            rebuilt_wheel,
            project_name=project_name,
            version=version,
            requires_python=requires_python,
        )
        _smoke_install(
            rebuilt_wheel,
            version=version,
            workspace=workspace,
            label="sdist-wheel",
        )

    print("integrated_agent_release_gate=PASS", flush=True)


if __name__ == "__main__":
    main()
