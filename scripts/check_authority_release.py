from __future__ import annotations

import os
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
    "tests/test_rfc_0033.py",
    "tests/test_v033_release.py",
)

_REQUIRED_AUTHORITY_TESTS = frozenset(
    {
        "tests/test_authority_contracts.py",
        "tests/test_authority_subject_binding.py",
        "tests/test_authority_freshness.py",
        "tests/test_authority_composition.py",
        "tests/test_authority_adversarial.py",
        "tests/test_authority_explain.py",
        "tests/test_authority_redaction.py",
        "tests/test_authority_security_review.py",
        "tests/test_rfc_0033.py",
        "tests/test_authority_release_gate.py",
    }
)

_REQUIRED_AUTHORITY_MODULES = frozenset(
    {
        "phoenix_os/authority/__init__.py",
        "phoenix_os/authority/catalog.py",
        "phoenix_os/authority/contracts.py",
        "phoenix_os/authority/freshness.py",
        "phoenix_os/authority/redaction.py",
        "phoenix_os/authority/service.py",
    }
)

_REQUIRED_INTEGRATION_FILES = frozenset(
    {
        "phoenix_os/control_plane/authority_cli.py",
        "phoenix_os/control_plane/authority_http.py",
        "phoenix_os/control_plane/authority_integration.py",
    }
)

_REQUIRED_RELEASE_HARDENING_FILES = (
    "README.md",
    "CHANGELOG.md",
    "docs/rfcs/RFC-0033-effective-authority-and-capability-non-amplification.md",
    "docs/migrations/v0.32.0-to-v0.33.0-effective-authority.md",
    "docs/releases/v0.33.0.md",
    "docs/security/RFC-0033-effective-authority-threat-model-review.md",
)

_REQUIRED_SDIST_DOCUMENTS = (
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "pyproject.toml",
    "docs/rfcs/RFC-0033-effective-authority-and-capability-non-amplification.md",
    "docs/migrations/v0.32.0-to-v0.33.0-effective-authority.md",
    "docs/releases/v0.33.0.md",
    "docs/security/RFC-0033-effective-authority-threat-model-review.md",
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


def _authority_test_files() -> tuple[str, ...]:
    discovered = tuple(
        path.relative_to(_ROOT).as_posix()
        for path in sorted((_ROOT / "tests").glob("test_authority*.py"))
    )
    for relative in _COMPANION_TESTS:
        if not (_ROOT / relative).is_file():
            raise RuntimeError(f"required authority companion test is missing: {relative}")
    available = frozenset((*discovered, *_COMPANION_TESTS))
    missing = sorted(_REQUIRED_AUTHORITY_TESTS - available)
    if missing:
        raise RuntimeError(
            "authority regression suite is missing required tests: " + ", ".join(missing)
        )
    return (*discovered, *_COMPANION_TESTS)


def _authority_source_files() -> tuple[str, ...]:
    source = _ROOT / "src" / "phoenix_os" / "authority"
    discovered = tuple(
        f"phoenix_os/authority/{path.relative_to(source).as_posix()}"
        for path in sorted(source.rglob("*.py"))
    )
    missing = sorted(_REQUIRED_AUTHORITY_MODULES - frozenset(discovered))
    if missing:
        raise RuntimeError("authority package is missing required modules: " + ", ".join(missing))
    unexpected = sorted(frozenset(discovered) - _REQUIRED_AUTHORITY_MODULES)
    if unexpected:
        raise RuntimeError(
            "authority package contains unreviewed modules: " + ", ".join(unexpected)
        )
    return discovered


def _validate_release_hardening_files() -> None:
    for relative in _REQUIRED_RELEASE_HARDENING_FILES:
        if not (_ROOT / relative).is_file():
            raise RuntimeError(f"required authority release file is missing: {relative}")


def _required_package_files() -> frozenset[str]:
    return frozenset(
        {
            "phoenix_os/__init__.py",
            "phoenix_os/py.typed",
            *_authority_source_files(),
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


def _validate_exact_authority_package_files(
    names: Sequence[str], *, prefix: str, label: str
) -> None:
    root = f"{prefix}phoenix_os/authority/"
    discovered = frozenset(
        name[len(prefix) :] for name in names if name.startswith(root) and not name.endswith("/")
    )
    missing = sorted(_REQUIRED_AUTHORITY_MODULES - discovered)
    if missing:
        raise RuntimeError(f"{label} is missing authority package files: " + ", ".join(missing))
    unexpected = sorted(discovered - _REQUIRED_AUTHORITY_MODULES)
    if unexpected:
        raise RuntimeError(
            f"{label} contains unexpected authority package files: " + ", ".join(unexpected)
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
        _validate_exact_authority_package_files(names, prefix="", label=f"wheel {wheel.name}")
        available = frozenset(names)
        missing = sorted(_required_package_files() - available)
        if missing:
            raise RuntimeError(
                f"wheel {wheel.name} is missing required authority files: " + ", ".join(missing)
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
    _validate_exact_authority_package_files(
        tuple(relative), prefix="src/", label=f"sdist {sdist.name}"
    )
    required = {
        *_REQUIRED_SDIST_DOCUMENTS,
        *{f"src/{name}" for name in _required_package_files()},
    }
    missing = sorted(required - relative)
    if missing:
        raise RuntimeError(
            f"sdist {sdist.name} is missing required authority files: " + ", ".join(missing)
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


def _smoke_install(wheel: Path, *, version: str, workspace: Path, label: str) -> None:
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
from importlib.metadata import version as distribution_version
from pathlib import Path
from uuid import UUID
import sys

import phoenix_os
from phoenix_os.authority import (
    BUILTIN_AUTHORITY_CATALOG,
    AuthorityFreshnessBinding,
    AuthorityIntent,
    AuthoritySubject,
    UnknownAuthorityOperationError,
    authority_intent_fingerprint,
    authority_subject_fingerprint,
)
from phoenix_os.policy import PrincipalType

assert distribution_version("phoenix-os") == {version!r}
assert Path(phoenix_os.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())

subject = AuthoritySubject(
    principal_type=PrincipalType.USER,
    principal="release-operator",
    session_id=UUID("10000000-0000-4000-8000-000000000033"),
    agent_id="release-agent",
    run_id="release-run",
)
assert authority_subject_fingerprint(subject).startswith("sha256:")

intent = AuthorityIntent(
    action="host.process.list",
    canonical_resource="host-automation:host:desktop/processes",
    parameter_digest="sha256:" + "0" * 64,
    freshness_bindings=(AuthorityFreshnessBinding("host.epoch", "release-epoch"),),
)
assert authority_intent_fingerprint(intent).startswith("sha256:")
entry = BUILTIN_AUTHORITY_CATALOG.validate_intent(intent)
assert entry.canonical_boundary == "host.process.list"

try:
    BUILTIN_AUTHORITY_CATALOG.require("host.shell.execute")
except UnknownAuthorityOperationError:
    pass
else:
    raise AssertionError("unknown protected operations must fail closed")
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


def main() -> None:
    project_name, version, requires_python = _project_metadata()
    if project_name != "phoenix-os":
        raise RuntimeError("authority release gate requires phoenix-os project metadata")
    if version != "0.33.0":
        raise RuntimeError("authority release gate requires version 0.33.0")

    tests = _authority_test_files()
    _authority_source_files()
    _validate_release_hardening_files()
    _run((sys.executable, "-m", "pytest", *tests))

    with tempfile.TemporaryDirectory(prefix="phoenix-authority-release-") as temp:
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
        wheel = _single_artifact(dist, "*.whl", label="wheel")
        sdist = _single_artifact(dist, "*.tar.gz", label="sdist")
        _validate_wheel(
            wheel,
            project_name=project_name,
            version=version,
            requires_python=requires_python,
        )
        _validate_sdist(sdist)
        _smoke_install(wheel, version=version, workspace=workspace, label="source-wheel")

        extracted = workspace / "extracted"
        extracted.mkdir()
        source = _extract_sdist(sdist, extracted)
        rebuilt = workspace / "rebuilt"
        rebuilt.mkdir()
        print("Rebuilding a wheel from the validated sdist", flush=True)
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
        rebuilt_wheel = _single_artifact(rebuilt, "*.whl", label="rebuilt wheel")
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

    print("authority_release_gate=PASS", flush=True)


if __name__ == "__main__":
    main()
