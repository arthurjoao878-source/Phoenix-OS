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
    "tests/test_inference_contracts.py",
    "tests/test_inference_codec.py",
    "tests/test_inference_fake_provider.py",
    "tests/test_inference_registry.py",
    "tests/test_inference_authorization.py",
    "tests/test_inference_credentials.py",
    "tests/test_inference_endpoints.py",
    "tests/test_inference_admission.py",
    "tests/test_inference_execution.py",
    "tests/test_inference_ollama.py",
    "tests/test_inference_streaming.py",
    "tests/test_inference_configuration.py",
    "tests/test_inference_service.py",
    "tests/test_inference_runtime_integration.py",
    "tests/test_inference_administration.py",
    "tests/test_control_plane_inference_http.py",
    "tests/test_control_plane_inference_dashboard.py",
    "tests/test_control_plane_inference_machine_http.py",
    "tests/test_inference_migration_guidance.py",
    "tests/test_inference_adrs.py",
    "tests/test_rfc_0026.py",
    "tests/test_v026_release.py",
)

_REQUIRED_SDIST_DOCUMENTS = (
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "pyproject.toml",
    "docs/releases/v0.26.0.md",
    "docs/rfcs/RFC-0026-secure-model-providers-and-inference-runtime.md",
    "docs/rfcs/RFC-0038-secure-real-model-provider-execution-and-integrated-agent-dogfood.md",
    "docs/migrations/v0.25.0-to-v0.26.0-inference.md",
    "docs/adrs/README.md",
    "docs/adrs/ADR-0011-provider-neutral-contracts-and-reviewed-inference-registry.md",
    "docs/adrs/ADR-0012-exact-inference-authorization-and-untrusted-model-output.md",
    "docs/adrs/ADR-0013-exact-credential-leases-and-fail-closed-provider-endpoints.md",
    "docs/adrs/ADR-0014-bounded-streaming-cancellation-and-no-transparent-retry.md",
    "docs/adrs/ADR-0015-opt-in-inference-runtime-and-separated-administration.md",
)

_REQUIRED_INTEGRATION_FILES = (
    "phoenix_os/configuration/dependencies.py",
    "phoenix_os/control_plane/__init__.py",
    "phoenix_os/control_plane/inference_http.py",
    "phoenix_os/control_plane/inference_machine_http.py",
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
    if not isinstance(name, str) or not name:
        raise RuntimeError("pyproject project name is missing")
    if not isinstance(version, str) or not version:
        raise RuntimeError("pyproject project version is missing")
    if not isinstance(requires_python, str) or not requires_python:
        raise RuntimeError("pyproject Python requirement is missing")
    return name, version, requires_python


def _inference_source_files() -> tuple[str, ...]:
    source = _ROOT / "src" / "phoenix_os" / "inference"
    files = tuple(f"phoenix_os/inference/{path.name}" for path in sorted(source.glob("*.py")))
    if not files:
        raise RuntimeError("inference package contains no Python modules")
    return files


def _required_package_files() -> frozenset[str]:
    return frozenset(
        {
            "phoenix_os/__init__.py",
            "phoenix_os/py.typed",
            *_inference_source_files(),
            *_REQUIRED_INTEGRATION_FILES,
        }
    )


def _validate_archive_names(
    names: Sequence[str],
    *,
    label: str,
) -> None:
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
        _validate_archive_names(
            names,
            label=f"wheel {wheel.name}",
        )
        available = frozenset(names)

        missing = sorted(_required_package_files() - available)
        if missing:
            raise RuntimeError(
                f"wheel {wheel.name} is missing required inference files: " + ", ".join(missing)
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


def _sdist_relative_names(
    archive: tarfile.TarFile,
) -> tuple[str, ...]:
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
            f"sdist {sdist.name} is missing required inference files: " + ", ".join(missing)
        )


def _extract_sdist(
    sdist: Path,
    destination: Path,
) -> Path:
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
    venv.EnvBuilder(
        with_pip=True,
        clear=True,
    ).create(environment)
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

import phoenix_os
from phoenix_os.control_plane.inference_http import (
    INFERENCE_CONTROL_PLANE_BASE_PATH,
    ControlPlaneInferenceHttpAdapter,
)
from phoenix_os.control_plane.inference_machine_http import (
    CONTROL_PLANE_INFERENCE_MACHINE_BASE_PATH,
    CONTROL_PLANE_INFERENCE_MACHINE_RESOURCE,
    ControlPlaneInferenceMachineAdministration,
)
from phoenix_os.inference import (
    INFERENCE_MODEL_ACTION,
    DeterministicModelProvider,
    InferenceAdmissionLimits,
    InferenceExecutionLimits,
    InferenceFinishReason,
    InferenceMessage,
    InferenceProviderConfiguration,
    InferenceRequest,
    InferenceRole,
    InferenceServiceConfiguration,
    ModelCapabilities,
    ModelCredentialPolicy,
    ModelDescriptor,
    ModelEndpointPolicy,
    ModelId,
    ModelProviderId,
    inference_model_resource,
)
from phoenix_os.inference.ollama import (
    OLLAMA_ENDPOINT_URL,
    OLLAMA_PROVIDER_ID,
    OllamaTransportLimits,
)
from phoenix_os.secrets import SecretRef


async def main() -> None:
    assert distribution_version("phoenix-os") == {version!r}
    assert Path(phoenix_os.__file__).resolve().is_relative_to(
        Path(sys.prefix).resolve()
    )
    assert OLLAMA_PROVIDER_ID == ModelProviderId("ollama-local")
    assert OLLAMA_ENDPOINT_URL == "http://127.0.0.1:11434/"
    ollama_limits = OllamaTransportLimits()
    assert ollama_limits.max_request_bytes == 1_048_576
    assert ollama_limits.max_response_bytes == 1_048_576

    provider_id = ModelProviderId("release-fake")
    model_id = ModelId("chat")
    descriptor = ModelDescriptor(
        provider_id=provider_id,
        model_id=model_id,
        provider_model_name="chat",
        capabilities=ModelCapabilities(
            complete=True,
            streaming=True,
        ),
    )
    configuration = InferenceServiceConfiguration(
        providers=(
            InferenceProviderConfiguration(provider_id),
        ),
        models=(descriptor,),
        execution_limits=InferenceExecutionLimits(),
        admission_limits=InferenceAdmissionLimits(
            global_concurrency=2,
            provider_concurrency=1,
            model_concurrency=1,
        ),
    )
    provider = DeterministicModelProvider(
        {{"chat": "packaged inference response"}},
        provider_id=provider_id,
        chunk_characters=8,
    )
    request = InferenceRequest(
        provider_id=provider_id,
        model_id=model_id,
        messages=(
            InferenceMessage(
                InferenceRole.SYSTEM,
                "be concise",
            ),
            InferenceMessage(
                InferenceRole.USER,
                "package smoke",
            ),
        ),
        max_output_tokens=8,
        created_at=datetime(
            2026,
            7,
            27,
            12,
            tzinfo=UTC,
        ),
        deadline=datetime(
            2026,
            7,
            27,
            12,
            1,
            tzinfo=UTC,
        ),
    )

    response = await provider.infer(request)
    chunks = [
        chunk
        async for chunk in provider.stream(request)
    ]

    assert configuration.provider_ids == (provider_id,)
    assert response.text == "packaged inference response"
    assert response.finish_reason is InferenceFinishReason.STOP
    assert chunks[-1].terminal is True
    assert sum(chunk.terminal for chunk in chunks) == 1
    assert "".join(
        chunk.text for chunk in chunks[:-1]
    ) == "packaged inference response"
    assert INFERENCE_MODEL_ACTION == "model.infer"
    assert inference_model_resource(
        provider_id,
        model_id,
    ) == "model-provider:release-fake/model:chat"

    endpoint = ModelEndpointPolicy(
        "https://api.example.com/v1"
    )
    credential = ModelCredentialPolicy(
        SecretRef(
            "release-credential",
            namespace="inference",
            version=1,
        )
    )
    secured_provider = InferenceProviderConfiguration(
        ModelProviderId("secured-hosted"),
        endpoint_policy=endpoint,
        credential_policy=credential,
    )
    assert endpoint.url == "https://api.example.com/v1"
    assert credential.secret_ref.version == 1
    assert "release-credential" not in repr(secured_provider)
    assert "api.example.com" not in repr(secured_provider)

    assert INFERENCE_CONTROL_PLANE_BASE_PATH == (
        "/v1/control-plane/inference"
    )
    assert ControlPlaneInferenceHttpAdapter.handles(
        "/v1/control-plane/inference/health"
    )
    assert CONTROL_PLANE_INFERENCE_MACHINE_BASE_PATH == (
        "/v1/control-plane/machine/inference"
    )
    assert (
        CONTROL_PLANE_INFERENCE_MACHINE_RESOURCE
        == "inference-machine"
    )
    assert (
        ControlPlaneInferenceMachineAdministration.__name__
        == "ControlPlaneInferenceMachineAdministration"
    )


asyncio.run(main())
"""
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONNOUSERSITE"] = "1"
    _run(
        (
            str(python),
            "-I",
            "-c",
            program,
        ),
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


def _validate_filename_version(
    path: Path,
    *,
    version: str,
) -> None:
    normalized = re.sub(r"[-_.]+", r"[-_.]", version)
    if (
        re.search(
            rf"[-_]{normalized}(?:[-_.]|$)",
            path.name,
        )
        is None
    ):
        raise RuntimeError(f"artifact filename does not contain version {version}: {path.name}")


def main() -> int:
    project_name, version, requires_python = _project_metadata()

    print(
        "Running RFC-0026/RFC-0038 inference security, endpoint, limits, "
        "streaming, provider, cancellation, administration, and "
        "compatibility suites.",
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
        prefix="phoenix-inference-release-",
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

        wheel = _single_artifact(
            artifacts,
            "*.whl",
            label="wheel",
        )
        sdist = _single_artifact(
            artifacts,
            "*.tar.gz",
            label="sdist",
        )
        _validate_filename_version(
            wheel,
            version=version,
        )
        _validate_filename_version(
            sdist,
            version=version,
        )
        _validate_wheel(
            wheel,
            project_name=project_name,
            version=version,
            requires_python=requires_python,
        )
        _validate_sdist(sdist)

        extracted = workspace / "extracted"
        extracted.mkdir()
        source = _extract_sdist(
            sdist,
            extracted,
        )
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
            "Installing inference artifacts into isolated offline environments.",
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

    print(
        "RFC-0026 inference release gate passed.",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
