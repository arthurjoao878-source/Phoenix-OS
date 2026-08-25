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
    "tests/test_agent_execution.py",
    "tests/test_agent_loop.py",
    "tests/test_agent_tools.py",
    "tests/test_authority_composition.py",
    "tests/test_authority_contracts.py",
    "tests/test_authority_redaction.py",
    "tests/test_rfc_0034.py",
    "tests/test_v034_release.py",
)
_REQUIRED_NETWORK_TESTS = frozenset(
    {
        "tests/test_network_egress_administration.py",
        "tests/test_network_egress_admission.py",
        "tests/test_network_egress_agent_tools.py",
        "tests/test_network_egress_authorization.py",
        "tests/test_network_egress_contracts.py",
        "tests/test_network_egress_freshness.py",
        "tests/test_network_egress_observability_adversarial.py",
        "tests/test_network_egress_observer.py",
        "tests/test_network_egress_profiles.py",
        "tests/test_network_egress_release_gate.py",
        "tests/test_network_egress_runtime.py",
        "tests/test_network_egress_security_review.py",
        "tests/test_network_egress_service.py",
        "tests/test_network_egress_ssrf_adversarial.py",
        "tests/test_network_egress_transport.py",
    }
)
_REQUIRED_NETWORK_MODULES = frozenset(
    {
        "phoenix_os/network_egress/__init__.py",
        "phoenix_os/network_egress/_admission.py",
        "phoenix_os/network_egress/_errors.py",
        "phoenix_os/network_egress/_transport.py",
        "phoenix_os/network_egress/administration.py",
        "phoenix_os/network_egress/agent_tools.py",
        "phoenix_os/network_egress/authorization.py",
        "phoenix_os/network_egress/contracts.py",
        "phoenix_os/network_egress/observer.py",
        "phoenix_os/network_egress/profiles.py",
        "phoenix_os/network_egress/runtime.py",
        "phoenix_os/network_egress/service.py",
    }
)
_REQUIRED_INTEGRATION_FILES = frozenset(
    {
        "phoenix_os/agent/execution.py",
        "phoenix_os/agent/loop.py",
        "phoenix_os/agent/tools.py",
        "phoenix_os/authority/catalog.py",
    }
)
_REQUIRED_RELEASE_HARDENING_FILES = (
    "README.md",
    "CHANGELOG.md",
    "docs/rfcs/RFC-0034-secure-network-egress-and-controlled-http-operations.md",
    "docs/migrations/v0.33.0-to-v0.34.0-secure-network-egress.md",
    "docs/releases/v0.34.0.md",
    "docs/security/RFC-0034-secure-network-egress-threat-model-review.md",
)
_REQUIRED_SDIST_DOCUMENTS = (
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "pyproject.toml",
    *_REQUIRED_RELEASE_HARDENING_FILES[2:],
)
_FORBIDDEN_ARCHIVE_COMPONENTS = frozenset({".env", ".git", "__pycache__"})
_FORBIDDEN_ARCHIVE_SUFFIXES = frozenset({".key", ".p12", ".pem", ".pfx", ".pyc", ".pyo"})
_EXPECTED_RELEASE_VERSION = "0.34.0"
_EXPECTED_WHEEL_NAME = "phoenix_os-0.34.0-py3-none-any.whl"
_EXPECTED_SDIST_NAME = "phoenix_os-0.34.0.tar.gz"


def _run(
    command: Sequence[str], *, cwd: Path = _ROOT, env: Mapping[str, str] | None = None
) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(tuple(command), cwd=cwd, env=None if env is None else dict(env), check=True)


def _project_metadata() -> tuple[str, str, str]:
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    if not isinstance(project, dict):
        raise RuntimeError("pyproject project metadata is invalid")
    name, version, requires_python = (
        project.get("name"),
        project.get("version"),
        project.get("requires-python"),
    )
    if not all(isinstance(value, str) and value for value in (name, version, requires_python)):
        raise RuntimeError("pyproject release metadata is incomplete")
    return name, version, requires_python


def _network_test_files() -> tuple[str, ...]:
    discovered = tuple(
        path.relative_to(_ROOT).as_posix()
        for path in sorted((_ROOT / "tests").glob("test_network_egress*.py"))
    )
    missing = sorted(_REQUIRED_NETWORK_TESTS - frozenset(discovered))
    if missing:
        raise RuntimeError(
            "network-egress regression suite is missing required tests: " + ", ".join(missing)
        )
    for relative in _COMPANION_TESTS:
        if not (_ROOT / relative).is_file():
            raise RuntimeError(f"required network-egress companion test is missing: {relative}")
    return (*discovered, *_COMPANION_TESTS)


def _network_source_files() -> tuple[str, ...]:
    source = _ROOT / "src" / "phoenix_os" / "network_egress"
    discovered = tuple(
        f"phoenix_os/network_egress/{path.relative_to(source).as_posix()}"
        for path in sorted(source.rglob("*.py"))
    )
    available = frozenset(discovered)
    missing = sorted(_REQUIRED_NETWORK_MODULES - available)
    unexpected = sorted(available - _REQUIRED_NETWORK_MODULES)
    if missing:
        raise RuntimeError(
            "network-egress package is missing required modules: " + ", ".join(missing)
        )
    if unexpected:
        raise RuntimeError(
            "network-egress package contains unreviewed modules: " + ", ".join(unexpected)
        )
    return discovered


def _required_package_files() -> frozenset[str]:
    return frozenset(
        {
            "phoenix_os/__init__.py",
            "phoenix_os/py.typed",
            *_network_source_files(),
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


def _validate_exact_network_package_files(names: Sequence[str], *, prefix: str, label: str) -> None:
    root = f"{prefix}phoenix_os/network_egress/"
    discovered = frozenset(
        name[len(prefix) :]
        for name in names
        if name.startswith(root) and name != root and not name.endswith("/")
    )
    missing = sorted(_REQUIRED_NETWORK_MODULES - discovered)
    unexpected = sorted(discovered - _REQUIRED_NETWORK_MODULES)
    if missing:
        raise RuntimeError(
            f"{label} is missing network-egress package files: " + ", ".join(missing)
        )
    if unexpected:
        raise RuntimeError(
            f"{label} contains unexpected network-egress package files: " + ", ".join(unexpected)
        )


def _validate_wheel(wheel: Path, *, project_name: str, version: str, requires_python: str) -> None:
    with zipfile.ZipFile(wheel) as archive:
        names = tuple(archive.namelist())
        _validate_archive_names(names, label=f"wheel {wheel.name}")
        _validate_exact_network_package_files(names, prefix="", label=f"wheel {wheel.name}")
        missing = sorted(_required_package_files() - frozenset(names))
        if missing:
            raise RuntimeError(
                f"wheel {wheel.name} is missing required network-egress files: "
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
    _validate_exact_network_package_files(
        tuple(relative), prefix="src/", label=f"sdist {sdist.name}"
    )
    required = {*_REQUIRED_SDIST_DOCUMENTS, *{f"src/{name}" for name in _required_package_files()}}
    missing = sorted(required - relative)
    if missing:
        raise RuntimeError(
            f"sdist {sdist.name} is missing required network-egress files: " + ", ".join(missing)
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
    smoke = workspace / f"smoke-{label}"
    smoke.mkdir()
    program = f"""
from importlib.metadata import version as distribution_version
from pathlib import Path
import hashlib
import sys

import phoenix_os
from phoenix_os.authority import BUILTIN_AUTHORITY_CATALOG
from phoenix_os.network_egress import (
    NETWORK_EGRESS_HEALTH_READ_PERMISSION,
    NETWORK_HTTP_REQUEST_ACTION,
    NetworkEgressOperationId,
    NetworkEgressProfileId,
    NetworkHttpRequest,
)

assert distribution_version("phoenix-os") == {version!r}
assert Path(phoenix_os.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())

request = NetworkHttpRequest(
    profile_id=NetworkEgressProfileId("release-profile"),
    operation_id=NetworkEgressOperationId("release-operation"),
    body=b"deterministic package smoke",
)
assert request.body_digest == (
    "sha256:" + hashlib.sha256(b"deterministic package smoke").hexdigest()
)

entry = BUILTIN_AUTHORITY_CATALOG.require(NETWORK_HTTP_REQUEST_ACTION)
assert entry.canonical_boundary == "network.http.request"
assert entry.accepts_resource(
    "network-egress:release-profile/generation:1/operation:release-operation"
)
assert (
    "tool.invoke",
    NETWORK_HTTP_REQUEST_ACTION,
) in BUILTIN_AUTHORITY_CATALOG.mediated_transitions
assert NETWORK_EGRESS_HEALTH_READ_PERMISSION == "network.egress.health.read"
"""
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONNOUSERSITE"] = "1"
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(key, None)
    _run((str(python), "-I", "-c", program), cwd=smoke, env=env)


def _release_artifact_names(version: str) -> tuple[str, str]:
    if version != _EXPECTED_RELEASE_VERSION:
        raise RuntimeError(
            "network-egress release gate requires version "
            f"{_EXPECTED_RELEASE_VERSION}; got {version}"
        )
    return _EXPECTED_WHEEL_NAME, _EXPECTED_SDIST_NAME


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
        raise RuntimeError("network-egress release gate requires phoenix-os project metadata")
    wheel_name, sdist_name = _release_artifact_names(version)
    tests = _network_test_files()
    _network_source_files()
    for relative in _REQUIRED_RELEASE_HARDENING_FILES:
        if not (_ROOT / relative).is_file():
            raise RuntimeError(f"required network-egress release file is missing: {relative}")
    _run((sys.executable, "-m", "pytest", *tests))
    with tempfile.TemporaryDirectory(prefix="phoenix-network-egress-release-") as temp:
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
            wheel, project_name=project_name, version=version, requires_python=requires_python
        )
        _validate_sdist(sdist)
        _smoke_install(wheel, version=version, workspace=workspace, label="source-wheel")
        extracted = workspace / "extracted"
        extracted.mkdir()
        source = _extract_sdist(sdist, extracted)
        rebuilt = workspace / "rebuilt"
        rebuilt.mkdir()
        print("Rebuilding a wheel from the validated sdist.", flush=True)
        _run(
            (sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(rebuilt)),
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
        _smoke_install(rebuilt_wheel, version=version, workspace=workspace, label="sdist-wheel")
    print("network_egress_release_gate=PASS", flush=True)


if __name__ == "__main__":
    main()
