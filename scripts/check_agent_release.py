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
    "tests/test_agent_contracts.py",
    "tests/test_agent_schemas.py",
    "tests/test_agent_codec.py",
    "tests/test_agent_tools.py",
    "tests/test_agent_registry.py",
    "tests/test_agent_fake.py",
    "tests/test_agent_authorization.py",
    "tests/test_agent_approval.py",
    "tests/test_agent_admission.py",
    "tests/test_agent_state.py",
    "tests/test_agent_execution.py",
    "tests/test_agent_loop.py",
    "tests/test_agent_configuration.py",
    "tests/test_agent_composition.py",
    "tests/test_agent_service.py",
    "tests/test_agent_observer.py",
    "tests/test_agent_administration.py",
    "tests/test_agent_runtime_integration.py",
    "tests/test_agent_migration_guidance.py",
    "tests/test_agent_adrs.py",
    "tests/test_agent_security_review.py",
    "tests/test_agent_release_gate.py",
    "tests/test_rfc_0027.py",
    "tests/test_v027_release.py",
)

_REQUIRED_SDIST_DOCUMENTS = (
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "pyproject.toml",
    "docs/releases/v0.27.0.md",
    "docs/rfcs/RFC-0027-secure-agent-loop-and-tool-calling.md",
    "docs/migrations/v0.26.0-to-v0.27.0-agent.md",
    "docs/security/RFC-0027-agent-threat-model-review.md",
    "docs/adrs/README.md",
    "docs/adrs/ADR-0016-server-owned-tool-registry-and-strict-agent-schemas.md",
    "docs/adrs/ADR-0017-independent-agent-model-tool-authorization-and-exact-approvals.md",
    "docs/adrs/ADR-0018-bounded-serial-agent-loop-and-no-transparent-retry.md",
    "docs/adrs/ADR-0019-untrusted-tool-results-and-content-free-agent-observability.md",
    "docs/adrs/ADR-0020-opt-in-agent-runtime-and-bounded-lifecycle.md",
)

_REQUIRED_INTEGRATION_FILES = (
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


def _agent_source_files() -> tuple[str, ...]:
    source = _ROOT / "src" / "phoenix_os" / "agent"
    files = tuple(f"phoenix_os/agent/{path.name}" for path in sorted(source.glob("*.py")))
    if not files:
        raise RuntimeError("agent package contains no Python modules")
    return files


def _required_package_files() -> frozenset[str]:
    return frozenset(
        {
            "phoenix_os/__init__.py",
            "phoenix_os/py.typed",
            *_agent_source_files(),
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
                f"wheel {wheel.name} is missing required agent files: " + ", ".join(missing)
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
            f"sdist {sdist.name} is missing required agent files: " + ", ".join(missing)
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

import phoenix_os
from phoenix_os.agent import (
    AGENT_RUN_ACTION,
    TOOL_INVOKE_ACTION,
    AgentId,
    AgentLoop,
    AgentMessage,
    AgentMessageRole,
    AgentObservabilityConfiguration,
    AgentRunRequest,
    AgentRunStatus,
    AgentServiceConfiguration,
    AgentToolConfiguration,
    BoundedAgentExecutor,
    ContentFreeAgentObserver,
    DeterministicFinalTurn,
    DeterministicModelTurnAdapter,
    DeterministicReadOnlyTool,
    DeterministicToolTurn,
    StaticToolResourceResolver,
    ToolDescriptor,
    ToolEffect,
    ToolId,
    ToolInputSchema,
    ToolInvocationRequest,
    ToolOutputSchema,
    ToolRegistry,
    ToolSchema,
    ToolSchemaType,
    agent_run_resource,
    tool_invocation_resource,
)
from phoenix_os.events import EventBus
from phoenix_os.inference import InferenceRequest, ModelId, ModelProviderId
from phoenix_os.policy import PrincipalType, SecurityContext


class RunAuthorizer:
    def __init__(self) -> None:
        self.calls = 0

    async def authorize(self, request: AgentRunRequest, context: SecurityContext) -> None:
        assert context.authenticated
        self.calls += 1


class ModelAuthorizer:
    def __init__(self) -> None:
        self.calls = 0

    async def authorize(self, request: InferenceRequest, context: SecurityContext) -> None:
        assert context.authenticated
        self.calls += 1


class ToolAuthorizer:
    def __init__(self) -> None:
        self.calls = 0

    async def authorize(
        self,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> None:
        assert context.authenticated
        assert descriptor.tool_id == request.tool_id
        self.calls += 1


def schema() -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={{
            "value": ToolSchema(
                kind=ToolSchemaType.STRING,
                min_length=1,
                max_length=64,
            )
        }},
        required=frozenset({{"value"}}),
    )


async def main() -> None:
    assert distribution_version("phoenix-os") == {version!r}
    assert Path(phoenix_os.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())

    now = datetime(2026, 7, 29, 12, tzinfo=UTC)
    tool_id = ToolId("release.lookup")
    descriptor = ToolDescriptor(
        tool_id=tool_id,
        name="Release lookup",
        description="One bounded packaged release smoke tool.",
        input_schema=ToolInputSchema(schema()),
        output_schema=ToolOutputSchema(schema()),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=4096,
        max_output_bytes=4096,
        timeout=timedelta(seconds=5),
        resolver_id="release.lookup.resolver",
        adapter_id="release.lookup.adapter",
    )
    configuration = AgentServiceConfiguration(
        agent_id=AgentId("release-agent"),
        provider_id=ModelProviderId("release-provider"),
        model_id=ModelId("release-model"),
        tools=(AgentToolConfiguration(descriptor),),
        observability=AgentObservabilityConfiguration(),
    )
    assert configuration.tool_ids == (tool_id,)
    assert "package smoke secret" not in repr(configuration)

    registry = ToolRegistry()
    adapter = DeterministicReadOnlyTool(
        tool_id,
        {{"value": "packaged result"}},
        adapter_id=descriptor.adapter_id,
    )
    registry.register_tool(
        descriptor,
        resolver=StaticToolResourceResolver(
            descriptor.resolver_id,
            "release/resource",
        ),
        adapter=adapter,
    )

    run_authorizer = RunAuthorizer()
    model_authorizer = ModelAuthorizer()
    tool_authorizer = ToolAuthorizer()
    loop = AgentLoop(
        run_authorizer=run_authorizer,
        model_authorizer=model_authorizer,
        tool_authorizer=tool_authorizer,
        model_adapter=DeterministicModelTurnAdapter((
            DeterministicToolTurn(tool_id, {{"value": "input"}}),
            DeterministicFinalTurn("packaged agent complete"),
        )),
        registry=registry,
        executor=BoundedAgentExecutor(clock=lambda: now),
        observer=ContentFreeAgentObserver(configuration, events=EventBus()),
        clock=lambda: now,
    )
    request = AgentRunRequest(
        agent_id=configuration.agent_id,
        provider_id=configuration.provider_id,
        model_id=configuration.model_id,
        messages=(AgentMessage(AgentMessageRole.USER, "package smoke"),),
        created_at=now,
        deadline=now + timedelta(minutes=5),
    )
    context = SecurityContext(
        principal="service:release",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )
    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.COMPLETED
    assert result.final_output == "packaged agent complete"
    assert result.model_turns == 2
    assert result.tool_calls == 1
    assert run_authorizer.calls == 1
    assert model_authorizer.calls == 2
    assert tool_authorizer.calls == 1
    assert len(adapter.requests) == 1
    assert AGENT_RUN_ACTION == "agent.run"
    assert TOOL_INVOKE_ACTION == "tool.invoke"
    assert agent_run_resource(configuration.agent_id) == "agent:release-agent"
    assert tool_invocation_resource(adapter.requests[0]) == (
        "tool:release.lookup/release/resource"
    )


asyncio.run(main())
"""
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONNOUSERSITE"] = "1"
    _run((str(python), "-I", "-c", program, program), cwd=smoke_directory, env=env)


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
        "Running RFC-0027 contracts, schemas, authorization, approval, limits, "
        "execution, cancellation, observability, Runtime, compatibility, and release suites.",
        flush=True,
    )
    _run((sys.executable, "-m", "pytest", "-q", *_SECURITY_TESTS))

    with tempfile.TemporaryDirectory(prefix="phoenix-agent-release-") as temporary:
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

        print("Installing agent artifacts into isolated offline environments.", flush=True)
        _smoke_install(wheel, version=version, workspace=workspace, label="wheel")
        _smoke_install(
            rebuilt_wheel,
            version=version,
            workspace=workspace,
            label="sdist-wheel",
        )

    print("RFC-0027 agent release gate passed.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
