from __future__ import annotations

import ast
import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_GATE = _ROOT / "scripts" / "check_webhook_release.py"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0024-durable-signed-webhooks-and-event-subscriptions.md"
_README = _ROOT / "README.md"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_CHECK_PS1 = _ROOT / "scripts" / "check.ps1"
_CHECK_SH = _ROOT / "scripts" / "check.sh"
_PYPROJECT = _ROOT / "pyproject.toml"

_REQUIRED_SECURITY_SUITES = (
    "tests/test_webhook_runtime_integration.py",
    "tests/test_webhook_transport.py",
    "tests/test_webhook_signing.py",
    "tests/test_webhook_recovery.py",
    "tests/test_webhook_manager.py",
    "tests/test_webhook_service_account_http.py",
    "tests/test_control_plane_service_account_replay.py",
)


def _gate() -> str:
    return _GATE.read_text(encoding="utf-8")


def test_release_gate_script_is_valid_python() -> None:
    ast.parse(_gate())


def test_release_gate_covers_required_security_suites() -> None:
    gate = _gate()
    for relative in _REQUIRED_SECURITY_SUITES:
        assert (_ROOT / relative).is_file()
        assert relative in gate


def test_release_gate_builds_and_validates_wheel_and_sdist() -> None:
    gate = _gate()
    required = (
        '"-m",\n                "build"',
        '"--no-isolation"',
        '"*.whl"',
        '"*.tar.gz"',
        "zipfile.ZipFile",
        'tarfile.open(sdist, mode="r:gz")',
        "Rebuilding a wheel from the validated sdist",
    )
    for phrase in required:
        assert phrase in gate


def test_release_gate_uses_offline_isolated_smoke_installs() -> None:
    gate = _gate()
    required = (
        "venv.EnvBuilder(with_pip=True, clear=True)",
        '"--no-deps"',
        '"--no-index"',
        '"-I"',
        'env["PYTHONNOUSERSITE"] = "1"',
        'env.pop("PYTHONPATH", None)',
    )
    for phrase in required:
        assert phrase in gate


def test_release_gate_is_wired_into_every_quality_entrypoint() -> None:
    command = "python scripts/check_webhook_release.py"
    assert _CI.read_text(encoding="utf-8").count(command) == 1
    assert _CHECK_PS1.read_text(encoding="utf-8").count(command) == 1
    assert _CHECK_SH.read_text(encoding="utf-8").count(command) == 1


def test_release_build_dependencies_are_declared() -> None:
    document = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    dependencies = document["project"]["optional-dependencies"]["dev"]

    assert any(item.startswith("build>=") for item in dependencies)
    assert any(item.startswith("hatchling>=") for item in dependencies)


def test_readme_documents_the_named_release_gate() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "## Webhook release gate" in readme
    assert "python scripts/check_webhook_release.py" in readme
    assert "offline isolated environments" in readme


def test_rfc_marks_security_and_packaging_gate_complete() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- [x] Regression, security, SSRF, replay, and packaging tests" in rfc
    assert "`scripts/check_webhook_release.py`" in rfc
    assert "wheel and sdist" in rfc
    assert "isolated offline environments" in rfc
