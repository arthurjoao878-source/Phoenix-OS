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
_COMPANION_TESTS = ("tests/test_rfc_0035.py",)
_REQUIRED_BROWSER_TESTS = frozenset(
    {
        "tests/test_browser_automation_adapter.py",
        "tests/test_browser_automation_administration.py",
        "tests/test_browser_automation_adrs.py",
        "tests/test_browser_automation_authorization.py",
        "tests/test_browser_automation_configuration.py",
        "tests/test_browser_automation_contracts.py",
        "tests/test_browser_automation_errors.py",
        "tests/test_browser_automation_fake.py",
        "tests/test_browser_automation_migration_guidance.py",
        "tests/test_browser_automation_network.py",
        "tests/test_browser_automation_observability_adversarial.py",
        "tests/test_browser_automation_observer.py",
        "tests/test_browser_automation_profiles.py",
        "tests/test_browser_automation_release_gate.py",
        "tests/test_browser_automation_runtime.py",
        "tests/test_browser_automation_s6.py",
        "tests/test_browser_automation_security_review.py",
        "tests/test_browser_automation_service.py",
    }
)
_REQUIRED_BROWSER_MODULES = frozenset(
    {
        "phoenix_os/browser_automation/__init__.py",
        "phoenix_os/browser_automation/adapter.py",
        "phoenix_os/browser_automation/administration.py",
        "phoenix_os/browser_automation/agent_tools.py",
        "phoenix_os/browser_automation/authorization.py",
        "phoenix_os/browser_automation/configuration.py",
        "phoenix_os/browser_automation/contracts.py",
        "phoenix_os/browser_automation/errors.py",
        "phoenix_os/browser_automation/fake.py",
        "phoenix_os/browser_automation/network.py",
        "phoenix_os/browser_automation/observer.py",
        "phoenix_os/browser_automation/profiles.py",
        "phoenix_os/browser_automation/runtime.py",
        "phoenix_os/browser_automation/service.py",
    }
)
_REQUIRED_INTEGRATION_FILES = frozenset(
    {
        "phoenix_os/agent/contracts.py",
        "phoenix_os/agent/schemas.py",
        "phoenix_os/agent/tools.py",
        "phoenix_os/authority/catalog.py",
        "phoenix_os/runtime/__init__.py",
    }
)
_REQUIRED_RELEASE_HARDENING_FILES = (
    "docs/rfcs/RFC-0035-secure-browser-automation-and-controlled-web-interaction.md",
    "docs/migrations/v0.34.0-to-v0.35.0-secure-browser-automation.md",
    "docs/security/RFC-0035-secure-browser-automation-threat-model-review.md",
    "docs/adrs/README.md",
    "docs/adrs/ADR-0064-web-content-and-browser-state-are-data.md",
    "docs/adrs/ADR-0065-server-owned-browser-profiles-and-navigation-targets.md",
    "docs/adrs/ADR-0066-opaque-stale-safe-browser-identities.md",
    "docs/adrs/ADR-0067-zero-effect-preparation-and-final-browser-admission.md",
)
_REQUIRED_SDIST_DOCUMENTS = (
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "pyproject.toml",
    *_REQUIRED_RELEASE_HARDENING_FILES,
)
_FORBIDDEN_ARCHIVE_COMPONENTS = frozenset({".env", ".git", "__pycache__"})
_FORBIDDEN_ARCHIVE_SUFFIXES = frozenset({".key", ".p12", ".pem", ".pfx", ".pyc", ".pyo"})
_VERSION_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+){2}$")


def _run(
    command: Sequence[str],
    *,
    cwd: Path = _ROOT,
    env: Mapping[str, str] | None = None,
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


def _browser_test_files() -> tuple[str, ...]:
    discovered = tuple(
        path.relative_to(_ROOT).as_posix()
        for path in sorted((_ROOT / "tests").glob("test_browser_automation*.py"))
    )
    missing = sorted(_REQUIRED_BROWSER_TESTS - frozenset(discovered))
    if missing:
        raise RuntimeError(
            "browser-automation regression suite is missing required tests: " + ", ".join(missing)
        )
    for relative in _COMPANION_TESTS:
        if not (_ROOT / relative).is_file():
            raise RuntimeError(f"required browser-automation companion test is missing: {relative}")
    return (*discovered, *_COMPANION_TESTS)


def _browser_source_files() -> tuple[str, ...]:
    source = _ROOT / "src" / "phoenix_os" / "browser_automation"
    discovered = tuple(
        f"phoenix_os/browser_automation/{path.relative_to(source).as_posix()}"
        for path in sorted(source.rglob("*.py"))
    )
    available = frozenset(discovered)
    missing = sorted(_REQUIRED_BROWSER_MODULES - available)
    unexpected = sorted(available - _REQUIRED_BROWSER_MODULES)
    if missing:
        raise RuntimeError(
            "browser-automation package is missing required modules: " + ", ".join(missing)
        )
    if unexpected:
        raise RuntimeError(
            "browser-automation package contains unreviewed modules: " + ", ".join(unexpected)
        )
    return discovered


def _required_package_files() -> frozenset[str]:
    return frozenset(
        {
            "phoenix_os/__init__.py",
            "phoenix_os/py.typed",
            *_browser_source_files(),
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


def _validate_exact_browser_package_files(
    names: Sequence[str],
    *,
    prefix: str,
    label: str,
) -> None:
    root = f"{prefix}phoenix_os/browser_automation/"
    discovered = frozenset(
        name[len(prefix) :]
        for name in names
        if name.startswith(root) and name != root and not name.endswith("/")
    )
    missing = sorted(_REQUIRED_BROWSER_MODULES - discovered)
    unexpected = sorted(discovered - _REQUIRED_BROWSER_MODULES)
    if missing:
        raise RuntimeError(
            f"{label} is missing browser-automation package files: " + ", ".join(missing)
        )
    if unexpected:
        raise RuntimeError(
            f"{label} contains unexpected browser-automation package files: "
            + ", ".join(unexpected)
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
        _validate_exact_browser_package_files(names, prefix="", label=f"wheel {wheel.name}")
        missing = sorted(_required_package_files() - frozenset(names))
        if missing:
            raise RuntimeError(
                f"wheel {wheel.name} is missing required browser-automation files: "
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
    _validate_exact_browser_package_files(
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
            f"sdist {sdist.name} is missing required browser-automation files: "
            + ", ".join(missing)
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
import sys

import phoenix_os
from phoenix_os.authority import BUILTIN_AUTHORITY_CATALOG
from phoenix_os.browser_automation import (
    BROWSER_ELEMENT_CLICK_ACTION,
    BROWSER_HEALTH_READ_PERMISSION,
    BROWSER_PAGE_NAVIGATE_ACTION,
    BROWSER_PAGE_READ_ACTION,
    BROWSER_SESSION_OPEN_ACTION,
    BrowserAdapterId,
    BrowserDestinationMode,
    BrowserNavigationTarget,
    BrowserNavigationTargetId,
    BrowserOrigin,
    BrowserProfile,
    BrowserProfileId,
)

assert distribution_version("phoenix-os") == {version!r}
assert Path(phoenix_os.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
assert BROWSER_HEALTH_READ_PERMISSION == "browser.health.read"

origin = BrowserOrigin(mode=BrowserDestinationMode.HOSTED_HTTPS, host="example.com")
target = BrowserNavigationTarget(
    target_id=BrowserNavigationTargetId("release-home"),
    origin=origin,
    request_target="/",
)
profile = BrowserProfile(
    profile_id=BrowserProfileId("release-browser"),
    generation=1,
    adapter_id=BrowserAdapterId("release-adapter"),
    allowed_origins=(origin,),
    initial_targets=(target,),
)
assert profile.require_target(target.target_id) == target

checks = (
    (
        BROWSER_SESSION_OPEN_ACTION,
        "browser:release-browser/generation:1",
    ),
    (
        BROWSER_PAGE_NAVIGATE_ACTION,
        "browser:release-browser/generation:1/session:00000000-0000-4000-8000-000000000001"
        "/page:00000000-0000-4000-8000-000000000002/revision:1",
    ),
    (
        BROWSER_PAGE_READ_ACTION,
        "browser:release-browser/generation:1/session:00000000-0000-4000-8000-000000000001"
        "/page:00000000-0000-4000-8000-000000000002/revision:1",
    ),
    (
        BROWSER_ELEMENT_CLICK_ACTION,
        "browser:release-browser/generation:1/session:00000000-0000-4000-8000-000000000001"
        "/page:00000000-0000-4000-8000-000000000002/revision:1"
        "/element:00000000-0000-4000-8000-000000000003",
    ),
)
for action, resource in checks:
    entry = BUILTIN_AUTHORITY_CATALOG.require(action)
    assert entry.canonical_boundary == action
    assert entry.accepts_resource(resource)
"""
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
    _run((str(python), "-I", "-c", program), cwd=smoke, env=env)


def _release_artifact_names(version: str) -> tuple[str, str]:
    if not isinstance(version, str) or _VERSION_PATTERN.fullmatch(version) is None:
        raise RuntimeError(f"unsupported browser release version: {version!r}")
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
        raise RuntimeError("browser-automation release gate requires phoenix-os project metadata")
    wheel_name, sdist_name = _release_artifact_names(version)
    tests = _browser_test_files()
    _browser_source_files()
    for relative in _REQUIRED_RELEASE_HARDENING_FILES:
        if not (_ROOT / relative).is_file():
            raise RuntimeError(f"required browser-automation release file is missing: {relative}")
    _run((sys.executable, "-m", "pytest", "-p", "no:cacheprovider", *tests))
    with tempfile.TemporaryDirectory(prefix="phoenix-browser-automation-release-") as temp:
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
        _smoke_install(wheel, version=version, workspace=workspace, label="source-wheel")

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
    print("browser_automation_release_gate=PASS", flush=True)


if __name__ == "__main__":
    main()
