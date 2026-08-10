from __future__ import annotations

import ast
import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_GATE = _ROOT / "scripts" / "check_durable_agent_release.py"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0028-durable-agent-runs-and-controlled-resumption.md"
_README = _ROOT / "README.md"
_MIGRATION = _ROOT / "docs" / "migrations" / "v0.27.0-to-v0.28.0-durable-agent.md"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_CHECK_PS1 = _ROOT / "scripts" / "check.ps1"
_CHECK_SH = _ROOT / "scripts" / "check.sh"
_PYPROJECT = _ROOT / "pyproject.toml"

_REQUIRED_DOCUMENTS = (
    "docs/rfcs/RFC-0028-durable-agent-runs-and-controlled-resumption.md",
    "docs/migrations/v0.27.0-to-v0.28.0-durable-agent.md",
    "docs/security/RFC-0028-durable-agent-threat-model-review.md",
    "docs/adrs/ADR-0021-untrusted-canonical-chained-durable-checkpoints.md",
    "docs/adrs/ADR-0022-fenced-leases-and-conditional-durable-mutation.md",
    "docs/adrs/ADR-0023-controlled-recovery-and-explicit-indeterminate-reconciliation.md",
    "docs/adrs/ADR-0024-opt-in-protected-payloads-and-content-free-durable-operations.md",
    "docs/adrs/ADR-0025-opt-in-runtime-owned-durable-lifecycle-retention-and-administration.md",
)

_COMPANION_TESTS = (
    "tests/test_durable_agent_migration_guidance.py",
    "tests/test_durable_agent_adrs.py",
    "tests/test_durable_agent_security_review.py",
    "tests/test_durable_agent_release_gate.py",
)


def _gate() -> str:
    return _GATE.read_text(encoding="utf-8")


def test_durable_agent_release_gate_script_is_valid_python() -> None:
    ast.parse(_gate())


def test_durable_agent_release_gate_discovers_complete_durable_suite() -> None:
    gate = _gate()
    assert 'glob("test_agent_durable_*.py")' in gate
    discovered = tuple(sorted((_ROOT / "tests").glob("test_agent_durable_*.py")))
    assert len(discovered) >= 20
    for path in discovered:
        assert path.is_file()
    for relative in _COMPANION_TESTS:
        assert (_ROOT / relative).is_file()
        assert relative in gate


def test_durable_agent_release_gate_requires_reviewed_documents() -> None:
    gate = _gate()
    for relative in _REQUIRED_DOCUMENTS:
        assert (_ROOT / relative).is_file()
        assert relative in gate


def test_durable_agent_release_gate_requires_every_durable_module() -> None:
    gate = _gate()
    assert 'glob("durable_*.py")' in gate
    durable_modules = tuple(sorted((_ROOT / "src" / "phoenix_os" / "agent").glob("durable_*.py")))
    assert len(durable_modules) >= 15
    for module in durable_modules:
        assert module.is_file()
    for phrase in (
        "phoenix_os/agent/__init__.py",
        "phoenix_os/configuration/dependencies.py",
        "phoenix_os/inference/__init__.py",
        "phoenix_os/policy/__init__.py",
    ):
        assert phrase in gate


def test_durable_agent_release_gate_builds_and_validates_wheel_and_sdist() -> None:
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


def test_durable_agent_release_gate_uses_offline_isolated_installs() -> None:
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


def test_durable_agent_release_gate_smokes_checkpoint_and_fencing() -> None:
    gate = _gate()
    for phrase in (
        "CanonicalCheckpointCodec",
        "CheckpointPayloadProfile.METADATA_ONLY",
        "InMemoryDurableRunStore",
        "seal_checkpoint_envelope",
        "lease_manager.acquire",
        "current.generation > stale.generation",
        "except AgentStateConflictError",
        "await store.append",
        "await store.list_history",
    ):
        assert phrase in gate


def test_durable_agent_release_gate_smokes_exact_durable_authority_names() -> None:
    gate = _gate()
    for phrase in (
        'AGENT_RESUME_ACTION == "agent.resume"',
        'AGENT_RECONCILE_ACTION == "agent.reconcile"',
        "durable_agent_run_resource(run_id)",
        "durable_reconciliation_resource(run_id, attempt_id)",
    ):
        assert phrase in gate


def test_durable_agent_release_gate_rejects_unsafe_archive_content() -> None:
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


def test_durable_agent_release_gate_is_wired_into_quality_entrypoints() -> None:
    command = "python scripts/check_durable_agent_release.py"
    assert _CI.read_text(encoding="utf-8").count(command) == 1
    assert _CHECK_PS1.read_text(encoding="utf-8").count(command) == 1
    assert _CHECK_SH.read_text(encoding="utf-8").count(command) == 1


def test_durable_agent_release_build_dependencies_are_declared() -> None:
    document = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    dependencies = document["project"]["optional-dependencies"]["dev"]
    assert any(item.startswith("build>=") for item in dependencies)
    assert any(item.startswith("hatchling>=") for item in dependencies)


def test_readme_and_migration_document_named_durable_gate() -> None:
    command = "python scripts/check_durable_agent_release.py"
    readme = _README.read_text(encoding="utf-8")
    migration = _MIGRATION.read_text(encoding="utf-8")
    assert "## Durable-agent release gate" in readme
    assert command in readme
    assert command in migration
    assert "isolated offline environments" in readme
    assert "without source-tree imports" in readme


def test_rfc_marks_durable_gate_and_offline_install_complete_only() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- [x] Durable-agent release gate" in rfc
    assert "- [x] Wheel and sdist isolated offline installation tests" in rfc
    assert "- [ ] Release notes and package version 0.28.0" in rfc
    assert "- [ ] Tag, artifacts, and checksums" in rfc
    assert "python scripts/check_durable_agent_release.py" in rfc


def test_gate_derives_current_package_version_until_final_release_slice() -> None:
    gate = _gate()
    assert 'version = project.get("version")' in gate
    assert 'distribution_version("phoenix-os") == {version!r}' in gate
    assert '"0.28.0"' not in gate
