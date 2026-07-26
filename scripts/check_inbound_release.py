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

_SECURITY_TESTS = (
    "tests/test_inbound_event_contracts.py",
    "tests/test_inbound_event_codec.py",
    "tests/test_inbound_event_memory.py",
    "tests/test_inbound_event_state.py",
    "tests/test_inbound_event_authentication.py",
    "tests/test_inbound_event_replay_idempotency.py",
    "tests/test_inbound_event_gateway.py",
    "tests/test_inbound_event_limits.py",
    "tests/test_inbound_event_http.py",
    "tests/test_inbound_event_secure_transport.py",
    "tests/test_inbound_event_publisher.py",
    "tests/test_inbound_event_recovery.py",
    "tests/test_inbound_event_manager.py",
    "tests/test_control_plane_inbound_management_http.py",
    "tests/test_control_plane_service_account_inbound_http.py",
    "tests/test_inbound_event_runtime_integration.py",
    "tests/test_v025_release.py",
)

_REQUIRED_SDIST_DOCUMENTS = (
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "pyproject.toml",
    "docs/releases/v0.25.0.md",
    "docs/rfcs/RFC-0025-secure-inbound-event-gateway-and-external-event-sources.md",
    "docs/migrations/v0.24.0-to-v0.25.0-inbound-events.md",
    "docs/adrs/README.md",
    "docs/adrs/ADR-0006-reviewed-inbound-schemas-and-normalization.md",
    "docs/adrs/ADR-0007-per-source-authentication-replay-and-idempotency.md",
    "docs/adrs/ADR-0008-shared-control-plane-listener-and-exact-inbound-routes.md",
    "docs/adrs/ADR-0009-durable-acceptance-and-at-least-once-publication.md",
    "docs/adrs/ADR-0010-opt-in-inbound-runtime-and-separated-administration.md",
)

_REQUIRED_INTEGRATION_FILES = (
    "phoenix_os/configuration/dependencies.py",
    "phoenix_os/control_plane/inbound_machine_http.py",
    "phoenix_os/control_plane/inbound_management_http.py",
    "phoenix_os/control_plane/runtime.py",
    "phoenix_os/control_plane/secure_http.py",
    "phoenix_os/control_plane/dashboard/app.css",
    "phoenix_os/control_plane/dashboard/app.js",
    "phoenix_os/control_plane/dashboard/index.html",
)

_FORBIDDEN_ARCHIVE_COMPONENTS = frozenset(
    {
        ".env",
        ".git",
        "__pycache__",
    }
)
_FORBIDDEN_ARCHIVE_SUFFIXES = frozenset(
    {
        ".key",
        ".p12",
        ".pem",
        ".pfx",
        ".pyc",
        ".pyo",
    }
)


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
    values = (name, version, requires_python)
    if not all(isinstance(value, str) and value for value in values):
        raise RuntimeError("pyproject release metadata is incomplete")
    return name, version, requires_python


def _inbound_source_files() -> tuple[str, ...]:
    source = _ROOT / "src" / "phoenix_os" / "inbound_events"
    files = tuple(f"phoenix_os/inbound_events/{path.name}" for path in sorted(source.glob("*.py")))
    if not files:
        raise RuntimeError("inbound event package contains no Python modules")
    return files


def _required_package_files() -> frozenset[str]:
    return frozenset(
        {
            "phoenix_os/__init__.py",
            "phoenix_os/py.typed",
            *_inbound_source_files(),
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
                f"wheel {wheel.name} is missing required inbound files: " + ", ".join(missing)
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
            f"sdist {sdist.name} is missing required inbound files: " + ", ".join(missing)
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
from datetime import timedelta
from importlib.metadata import version as distribution_version
from pathlib import Path
import sys

import phoenix_os
from phoenix_os.control_plane.inbound_machine_http import (
    CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH,
    CONTROL_PLANE_INBOUND_MACHINE_RESOURCE,
)
from phoenix_os.control_plane.inbound_management_http import (
    INBOUND_MANAGEMENT_BASE_PATH,
    ControlPlaneInboundManagementHttpAdapter,
)
from phoenix_os.inbound_events import (
    INBOUND_HTTP_PREFIX,
    INBOUND_SUBMIT_ACTION,
    InboundAdmissionLimitPolicy,
    InboundEventSchema,
    InboundPublicationRetryPolicy,
    InboundServiceAccountPolicy,
    canonical_inbound_json_bytes,
)

assert distribution_version("phoenix-os") == {version!r}
assert Path(phoenix_os.__file__).resolve().is_relative_to(
    Path(sys.prefix).resolve()
)

schema = InboundEventSchema(
    event_type="release.completed",
    event_schema_version=1,
    internal_event_type="external.release.completed",
    required_fields=frozenset({{"release"}}),
)
source_policy = InboundServiceAccountPolicy(
    "inbound-source:00000000-0000-4000-8000-000000000025"
)
retry = InboundPublicationRetryPolicy(max_attempts=3)
limits = InboundAdmissionLimitPolicy()
payload = canonical_inbound_json_bytes({{"release": "v0.25.0"}})

assert schema.allowed_fields == frozenset({{"release"}})
assert source_policy.required_action == INBOUND_SUBMIT_ACTION
assert INBOUND_SUBMIT_ACTION == "inbound_event.submit"
assert retry.delay_after(1) == timedelta(seconds=1)
assert limits.global_max_concurrency > 0
assert payload == b'{{"release":"v0.25.0"}}'
assert INBOUND_HTTP_PREFIX == "/v1/control-plane/inbound/"
assert INBOUND_MANAGEMENT_BASE_PATH == "/v1/control-plane/inbound"
assert CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH == (
    "/v1/control-plane/machine/inbound"
)
assert CONTROL_PLANE_INBOUND_MACHINE_RESOURCE == "inbound-machine"
assert ControlPlaneInboundManagementHttpAdapter.handles(
    "/v1/control-plane/inbound/health"
)
"""
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONNOUSERSITE"] = "1"
    _run(
        (str(python), "-I", "-c", program),
        cwd=smoke_directory,
        env=env,
    )


def _single_artifact(
    directory: Path,
    pattern: str,
    *,
    label: str,
) -> Path:
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
        "Running RFC-0025 regression, authentication, replay, "
        "admission, and administration suites.",
        flush=True,
    )
    _run(
        (
            sys.executable,
            "-m",
            "pytest",
            "-q",
            *_SECURITY_TESTS,
        )
    )

    with tempfile.TemporaryDirectory(
        prefix="phoenix-inbound-release-",
    ) as temporary:
        workspace = Path(temporary)
        artifacts = workspace / "dist"
        artifacts.mkdir()

        print(
            "Building wheel and sdist without network isolation.",
            flush=True,
        )
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
        sdist = _single_artifact(
            artifacts,
            "*.tar.gz",
            label="sdist",
        )
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

        print(
            "Rebuilding a wheel from the validated sdist.",
            flush=True,
        )
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
        _validate_filename_version(
            rebuilt_wheel,
            version=version,
        )
        _validate_wheel(
            rebuilt_wheel,
            project_name=project_name,
            version=version,
            requires_python=requires_python,
        )

        print(
            "Installing inbound artifacts into isolated offline environments.",
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

    print("RFC-0025 inbound release gate passed.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
