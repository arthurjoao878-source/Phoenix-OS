from __future__ import annotations

import ast
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_GATE = _ROOT / "scripts" / "check_multi_agent_release.py"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0029-secure-multi-agent-coordination-and-delegation.md"
_MIGRATION = _ROOT / "docs" / "migrations" / "v0.28.0-to-v0.29.0-multi-agent.md"
_SECURITY = _ROOT / "docs" / "security" / "RFC-0029-multi-agent-threat-model-review.md"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_CHECK_PS1 = _ROOT / "scripts" / "check.ps1"
_CHECK_SH = _ROOT / "scripts" / "check.sh"


def _gate() -> str:
    return _GATE.read_text(encoding="utf-8")


def test_multi_agent_gate_is_valid_python_and_discovers_coordination_suite() -> None:
    gate = _gate()
    ast.parse(gate)
    assert 'glob("test_agent_coordination*.py")' in gate
    discovered = tuple(sorted((_ROOT / "tests").glob("test_agent_coordination*.py")))
    assert len(discovered) >= 10
    for path in discovered:
        assert path.is_file()


def test_multi_agent_gate_requires_release_documents_and_all_coordination_modules() -> None:
    gate = _gate()
    for path in (_RFC, _MIGRATION, _SECURITY):
        assert path.is_file()
        assert path.relative_to(_ROOT).as_posix() in gate
    assert 'glob("coordination*.py")' in gate
    modules = tuple(sorted((_ROOT / "src" / "phoenix_os" / "agent").glob("coordination*.py")))
    assert len(modules) >= 10
    for module in modules:
        assert f"phoenix_os/agent/{module.name}" in gate or 'glob("coordination*.py")' in gate


def test_multi_agent_gate_builds_rebuilds_and_installs_offline() -> None:
    gate = _gate()
    for phrase in (
        '"build"',
        '"--no-isolation"',
        '"*.whl"',
        '"*.tar.gz"',
        "zipfile.ZipFile",
        'tarfile.open(sdist, mode="r:gz")',
        "Rebuilding a wheel from the validated sdist",
        "venv.EnvBuilder",
        '"--no-deps"',
        '"--no-index"',
        '"-I"',
        'env["PYTHONNOUSERSITE"] = "1"',
        'env.pop("PYTHONPATH", None)',
    ):
        assert phrase in gate


def test_multi_agent_gate_smokes_exact_authority_and_durable_identity() -> None:
    gate = _gate()
    for phrase in (
        'AGENT_DELEGATE_ACTION == "agent.delegate"',
        "agent_delegation_resource(",
        "InMemoryDurableDelegationStore",
        "DurableDelegationRecord",
        "await store.create(record, limits=limits, root_budget_limit=root_budget)",
        "await store.compare_and_swap",
        "child_run_id == child_run",
    ):
        assert phrase in gate


def test_multi_agent_gate_rejects_unsafe_archive_content() -> None:
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


def test_multi_agent_gate_is_wired_correctly_into_every_quality_entrypoint() -> None:
    command = "python scripts/check_multi_agent_release.py"
    durable = "python scripts/check_durable_agent_release.py"

    ci_lines = _CI.read_text(encoding="utf-8").splitlines()
    assert f"      - run: {durable}" in ci_lines
    assert f"      - run: {command}" in ci_lines
    assert durable not in ci_lines
    assert command not in ci_lines

    assert _CHECK_PS1.read_text(encoding="utf-8").count(command) == 1
    assert _CHECK_SH.read_text(encoding="utf-8").count(command) == 1


def test_multi_agent_gate_derives_current_package_version_from_pyproject() -> None:
    gate = _gate()
    assert 'version = project.get("version")' in gate
    assert 'distribution_version("phoenix-os") == {version!r}' in gate
