from __future__ import annotations

import ast
import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_GATE = _ROOT / "scripts" / "check_agent_release.py"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0027-secure-agent-loop-and-tool-calling.md"
_README = _ROOT / "README.md"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_CHECK_PS1 = _ROOT / "scripts" / "check.ps1"
_CHECK_SH = _ROOT / "scripts" / "check.sh"
_PYPROJECT = _ROOT / "pyproject.toml"

_REQUIRED_SECURITY_SUITES = (
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
    "tests/test_rfc_0027.py",
    "tests/test_v027_release.py",
)

_REQUIRED_DOCUMENTS = (
    "docs/releases/v0.27.0.md",
    "docs/rfcs/RFC-0027-secure-agent-loop-and-tool-calling.md",
    "docs/migrations/v0.26.0-to-v0.27.0-agent.md",
    "docs/security/RFC-0027-agent-threat-model-review.md",
    "docs/adrs/ADR-0016-server-owned-tool-registry-and-strict-agent-schemas.md",
    "docs/adrs/ADR-0017-independent-agent-model-tool-authorization-and-exact-approvals.md",
    "docs/adrs/ADR-0018-bounded-serial-agent-loop-and-no-transparent-retry.md",
    "docs/adrs/ADR-0019-untrusted-tool-results-and-content-free-agent-observability.md",
    "docs/adrs/ADR-0020-opt-in-agent-runtime-and-bounded-lifecycle.md",
)


def _gate() -> str:
    return _GATE.read_text(encoding="utf-8")


def test_agent_release_gate_script_is_valid_python() -> None:
    ast.parse(_gate())


def test_agent_release_gate_covers_required_security_suites() -> None:
    gate = _gate()
    for relative in _REQUIRED_SECURITY_SUITES:
        assert (_ROOT / relative).is_file()
        assert relative in gate


def test_agent_release_gate_requires_package_contract_documents() -> None:
    gate = _gate()
    for relative in _REQUIRED_DOCUMENTS:
        assert (_ROOT / relative).is_file()
        assert relative in gate


def test_agent_release_gate_validates_all_modules_and_runtime_integration() -> None:
    gate = _gate()
    for phrase in (
        '"phoenix_os/agent/{path.name}"',
        "phoenix_os/configuration/dependencies.py",
        "phoenix_os/inference/__init__.py",
        "phoenix_os/policy/__init__.py",
    ):
        assert phrase in gate


def test_agent_release_gate_builds_and_validates_wheel_and_sdist() -> None:
    gate = _gate()
    for phrase in (
        '"build"',
        '"--no-isolation"',
        '"*.whl"',
        '"*.tar.gz"',
        "zipfile.ZipFile",
        'tarfile.open(sdist, mode="r:gz")',
        "Rebuilding a wheel from the validated sdist",
        "_validate_filename_version",
    ):
        assert phrase in gate


def test_agent_release_gate_uses_offline_isolated_smoke_installs() -> None:
    gate = _gate()
    for phrase in (
        "venv.EnvBuilder",
        "with_pip=True",
        '"--no-deps"',
        '"--no-index"',
        '"-I"',
        'env["PYTHONNOUSERSITE"] = "1"',
        'env.pop("PYTHONPATH", None)',
        "Path(sys.prefix).resolve()",
    ):
        assert phrase in gate


def test_agent_release_gate_smokes_packaged_execution_and_authority() -> None:
    gate = _gate()
    for phrase in (
        "DeterministicModelTurnAdapter",
        "DeterministicToolTurn",
        "DeterministicFinalTurn",
        "DeterministicReadOnlyTool",
        "AgentLoop",
        "await loop.run(request, context)",
        'AGENT_RUN_ACTION == "agent.run"',
        'TOOL_INVOKE_ACTION == "tool.invoke"',
        "model_authorizer.calls == 2",
        "tool_authorizer.calls == 2",
    ):
        assert phrase in gate


def test_agent_release_gate_smokes_strict_tools_configuration_and_observation() -> None:
    gate = _gate()
    for phrase in (
        "ToolSchemaType.OBJECT",
        "ToolInputSchema",
        "ToolOutputSchema",
        "StaticToolResourceResolver",
        "AgentServiceConfiguration",
        "AgentToolConfiguration",
        "AgentObservabilityConfiguration",
        "ContentFreeAgentObserver",
        "configuration.tool_ids == (tool_id,)",
    ):
        assert phrase in gate


def test_agent_release_gate_rejects_unsafe_archive_content() -> None:
    gate = _gate()
    for phrase in (
        '".env"',
        '".git"',
        '"__pycache__"',
        '".key"',
        '".pem"',
        '".pfx"',
        'path.is_absolute() or ".." in path.parts',
        "member.issym() or member.islnk()",
    ):
        assert phrase in gate


def test_agent_release_gate_is_wired_into_every_quality_entrypoint() -> None:
    command = "python scripts/check_agent_release.py"
    assert _CI.read_text(encoding="utf-8").count(command) == 1
    assert _CHECK_PS1.read_text(encoding="utf-8").count(command) == 1
    assert _CHECK_SH.read_text(encoding="utf-8").count(command) == 1


def test_agent_release_build_dependencies_are_declared() -> None:
    document = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    dependencies = document["project"]["optional-dependencies"]["dev"]
    assert any(item.startswith("build>=") for item in dependencies)
    assert any(item.startswith("hatchling>=") for item in dependencies)


def test_readme_documents_named_agent_release_gate() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "## Agent release gate" in readme
    assert "python scripts/check_agent_release.py" in readme
    assert "isolated offline environments" in readme
    assert "strict tool cycle" in readme


def test_rfc_marks_agent_security_and_packaging_gate_complete() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- [x] Agent and tool-calling release gate" in rfc
    assert "- [x] Wheel and sdist isolated offline installation tests" in rfc
    assert "`scripts/check_agent_release.py`" in rfc
    assert "without source-tree imports" in rfc


def test_agent_release_gate_includes_v027_release_metadata() -> None:
    gate = _gate()
    for phrase in (
        '"tests/test_v027_release.py"',
        '"CHANGELOG.md"',
        '"docs/releases/v0.27.0.md"',
    ):
        assert phrase in gate
