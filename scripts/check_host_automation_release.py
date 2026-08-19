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
    "tests/test_rfc_0032.py",
    "tests/test_v032_release.py",
)

_REQUIRED_HOST_AUTOMATION_TESTS = frozenset(
    {
        "tests/test_host_automation_administration.py",
        "tests/test_host_automation_adrs.py",
        "tests/test_host_automation_agent_control_tools.py",
        "tests/test_host_automation_agent_tools.py",
        "tests/test_host_automation_approval.py",
        "tests/test_host_automation_authorization.py",
        "tests/test_host_automation_clipboard_hardening.py",
        "tests/test_host_automation_contracts.py",
        "tests/test_host_automation_durable_recovery.py",
        "tests/test_host_automation_errors.py",
        "tests/test_host_automation_fake.py",
        "tests/test_host_automation_migration_guidance.py",
        "tests/test_host_automation_observer.py",
        "tests/test_host_automation_release_gate.py",
        "tests/test_host_automation_security_review.py",
        "tests/test_host_automation_service.py",
        "tests/test_host_automation_windows.py",
        "tests/test_host_automation_windows_clipboard_read.py",
        "tests/test_host_automation_windows_clipboard_write.py",
        "tests/test_host_automation_windows_close.py",
        "tests/test_host_automation_windows_discovery.py",
        "tests/test_host_automation_windows_dogfood.py",
        "tests/test_host_automation_windows_focus.py",
        "tests/test_host_automation_windows_launch.py",
    }
)

_REQUIRED_HOST_AUTOMATION_MODULES = frozenset(
    {
        "phoenix_os/host_automation/__init__.py",
        "phoenix_os/host_automation/administration.py",
        "phoenix_os/host_automation/agent_control_tools.py",
        "phoenix_os/host_automation/agent_tools.py",
        "phoenix_os/host_automation/approval.py",
        "phoenix_os/host_automation/authorization.py",
        "phoenix_os/host_automation/contracts.py",
        "phoenix_os/host_automation/errors.py",
        "phoenix_os/host_automation/fake.py",
        "phoenix_os/host_automation/observer.py",
        "phoenix_os/host_automation/service.py",
        "phoenix_os/host_automation/windows.py",
        "phoenix_os/host_automation/windows_clipboard.py",
        "phoenix_os/host_automation/windows_effects.py",
    }
)

_REQUIRED_RELEASE_HARDENING_FILES = (
    "README.md",
    "docs/rfcs/RFC-0032-secure-host-automation-and-desktop-control.md",
    "docs/migrations/v0.31.0-to-v0.32.0-secure-host-automation.md",
    "docs/adrs/ADR-0060-host-state-is-data-effects-require-fresh-authority.md",
    "docs/adrs/ADR-0061-server-owned-configured-application-profiles.md",
    "docs/adrs/ADR-0062-opaque-phoenix-host-identities.md",
    "docs/adrs/ADR-0063-immediate-ui-toctou-revalidation.md",
    "scripts/dogfood_host_automation_windows.py",
    "src/phoenix_os/configuration/dependencies.py",
)

_REQUIRED_SDIST_DOCUMENTS = (
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "pyproject.toml",
    "docs/releases/v0.32.0.md",
    "docs/rfcs/RFC-0032-secure-host-automation-and-desktop-control.md",
    "docs/migrations/v0.31.0-to-v0.32.0-secure-host-automation.md",
    "docs/security/RFC-0032-host-automation-threat-model-review.md",
    "docs/adrs/README.md",
    "docs/adrs/ADR-0060-host-state-is-data-effects-require-fresh-authority.md",
    "docs/adrs/ADR-0061-server-owned-configured-application-profiles.md",
    "docs/adrs/ADR-0062-opaque-phoenix-host-identities.md",
    "docs/adrs/ADR-0063-immediate-ui-toctou-revalidation.md",
)

_REQUIRED_INTEGRATION_FILES = (
    "phoenix_os/__init__.py",
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


def _host_automation_test_files() -> tuple[str, ...]:
    discovered = tuple(
        path.relative_to(_ROOT).as_posix()
        for path in sorted((_ROOT / "tests").glob("test_host_automation*.py"))
    )
    missing = sorted(_REQUIRED_HOST_AUTOMATION_TESTS - frozenset(discovered))
    if missing:
        raise RuntimeError(
            "host-automation regression suite is missing required tests: " + ", ".join(missing)
        )

    for relative in _COMPANION_TESTS:
        if not (_ROOT / relative).is_file():
            raise RuntimeError(f"required host-automation companion test is missing: {relative}")
    return (*discovered, *_COMPANION_TESTS)


def _host_automation_source_files() -> tuple[str, ...]:
    source = _ROOT / "src" / "phoenix_os" / "host_automation"
    discovered = tuple(
        f"phoenix_os/host_automation/{path.name}" for path in sorted(source.glob("*.py"))
    )
    missing = sorted(_REQUIRED_HOST_AUTOMATION_MODULES - frozenset(discovered))
    if missing:
        raise RuntimeError(
            "host-automation package is missing required modules: " + ", ".join(missing)
        )
    return discovered


def _validate_release_hardening_files() -> None:
    for relative in _REQUIRED_RELEASE_HARDENING_FILES:
        if not (_ROOT / relative).is_file():
            raise RuntimeError(f"required host-automation release file is missing: {relative}")

    security_reviews = tuple(sorted((_ROOT / "docs" / "security").glob("RFC-0032-*.md")))
    if not security_reviews:
        raise RuntimeError("required RFC-0032 security review is missing")


def _required_package_files() -> frozenset[str]:
    return frozenset(
        {
            "phoenix_os/__init__.py",
            "phoenix_os/py.typed",
            *_host_automation_source_files(),
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
                f"wheel {wheel.name} is missing required host-automation files: "
                + ", ".join(missing)
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
            f"sdist {sdist.name} is missing required host-automation files: " + ", ".join(missing)
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
from importlib.metadata import version as distribution_version
from pathlib import Path
import sys

import phoenix_os
from phoenix_os.host_automation import (
    HOST_APPLICATION_CLOSE_ACTION,
    HOST_APPLICATION_LAUNCH_ACTION,
    HOST_CLIPBOARD_READ_ACTION,
    HOST_CLIPBOARD_WRITE_ACTION,
    HOST_PROCESS_LIST_ACTION,
    HOST_WINDOW_FOCUS_ACTION,
    HOST_WINDOW_LIST_ACTION,
    DeterministicHostAutomationAdapter,
    HostAutomationService,
    HostClipboardReadRequest,
    HostClipboardWriteRequest,
    HostProcessListRequest,
    PolicyEngineHostAutomationAuthorizer,
)
from phoenix_os.policy import PolicyEffect, PolicyEngine, PolicyRule, PrincipalType, SecurityContext


async def main() -> None:
    assert distribution_version("phoenix-os") == {version!r}
    assert Path(phoenix_os.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())

    assert (
        HOST_PROCESS_LIST_ACTION,
        HOST_WINDOW_LIST_ACTION,
        HOST_APPLICATION_LAUNCH_ACTION,
        HOST_WINDOW_FOCUS_ACTION,
        HOST_APPLICATION_CLOSE_ACTION,
        HOST_CLIPBOARD_WRITE_ACTION,
        HOST_CLIPBOARD_READ_ACTION,
    ) == (
        "host.process.list",
        "host.window.list",
        "host.app.launch",
        "host.window.focus",
        "host.app.close",
        "host.clipboard.write",
        "host.clipboard.read",
    )

    adapter = DeterministicHostAutomationAdapter(host_id="release-host")
    policy = PolicyEngine((PolicyRule("release-smoke", PolicyEffect.ALLOW),))
    service = HostAutomationService(
        adapter=adapter,
        authorizer=PolicyEngineHostAutomationAuthorizer(policy),
    )
    context = SecurityContext(
        principal="service:release-smoke",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )

    processes = await service.list_processes(
        HostProcessListRequest(host_id=adapter.host_id, limit=4),
        context,
    )
    assert processes.host_id == adapter.host_id
    assert processes.host_epoch == adapter.host_epoch
    assert not processes.truncated

    probe = "packaged host automation release smoke"
    written = await service.write_clipboard(
        HostClipboardWriteRequest(host_id=adapter.host_id, text=probe),
        context,
    )
    assert written.written_characters == len(probe)
    read = await service.read_clipboard(
        HostClipboardReadRequest(host_id=adapter.host_id),
        context,
    )
    assert read.text == probe

    await service.close()
    assert service.closed
    assert adapter.closed


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
    source_files = _host_automation_source_files()
    _validate_release_hardening_files()

    print(
        "Running RFC-0032 host-automation contracts, authorization, Windows adapter, "
        "agent-tool, lifecycle, migration, ADR, security-review, and named release suites.",
        flush=True,
    )
    print(f"Validated {len(source_files)} required host-automation source modules.", flush=True)
    _run((sys.executable, "-m", "pytest", "-q", *_host_automation_test_files()))

    with tempfile.TemporaryDirectory(prefix="phoenix-host-automation-release-") as temporary:
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

        print(
            "Installing both wheel forms offline and running isolated deterministic "
            "host-automation smoke validation.",
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
            label="rebuilt",
        )

    print(
        f"RFC-0032 host-automation named release and offline package gate passed "
        f"for {project_name} {version}.",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
