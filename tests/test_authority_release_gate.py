from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_GATE = _ROOT / "scripts" / "check_authority_release.py"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_CHECK_PS1 = _ROOT / "scripts" / "check.ps1"
_CHECK_SH = _ROOT / "scripts" / "check.sh"
_README = _ROOT / "README.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0033-effective-authority-and-capability-non-amplification.md"


def test_authority_release_gate_covers_normative_suite_and_package_surface() -> None:
    text = _GATE.read_text(encoding="utf-8")
    for phrase in (
        'glob("test_authority*.py")',
        '"tests/test_authority_contracts.py"',
        '"tests/test_authority_subject_binding.py"',
        '"tests/test_authority_freshness.py"',
        '"tests/test_authority_composition.py"',
        '"tests/test_authority_adversarial.py"',
        '"tests/test_authority_explain.py"',
        '"tests/test_authority_redaction.py"',
        '"tests/test_authority_security_review.py"',
        '"tests/test_rfc_0033.py"',
        '"tests/test_authority_release_gate.py"',
        '"tests/test_v033_release.py"',
        '"phoenix_os/authority/catalog.py"',
        '"phoenix_os/authority/contracts.py"',
        '"phoenix_os/authority/freshness.py"',
        '"phoenix_os/authority/redaction.py"',
        '"phoenix_os/authority/service.py"',
        '"phoenix_os/control_plane/authority_cli.py"',
        '"docs/security/RFC-0033-effective-authority-threat-model-review.md"',
    ):
        assert phrase in text


def test_authority_release_gate_rejects_unreviewed_nested_authority_package_files() -> None:
    text = _GATE.read_text(encoding="utf-8")
    for phrase in (
        'rglob("*.py")',
        "_validate_exact_authority_package_files(",
        "unexpected authority package files",
        'prefix=""',
        'prefix="src/"',
    ):
        assert phrase in text


def test_authority_release_gate_builds_validates_and_rebuilds_packages() -> None:
    text = _GATE.read_text(encoding="utf-8")
    for phrase in (
        "import tarfile",
        "import zipfile",
        "_REQUIRED_SDIST_DOCUMENTS",
        "_validate_archive_names(",
        "_validate_wheel(",
        'tarfile.open(sdist, mode="r:gz")',
        '"build"',
        '"--no-isolation"',
        "Rebuilding a wheel from the validated sdist",
    ):
        assert phrase in text


def test_authority_release_gate_uses_offline_isolated_non_authoritative_smoke() -> None:
    text = _GATE.read_text(encoding="utf-8")
    for phrase in (
        "import venv",
        '"--no-deps"',
        '"--no-index"',
        "PYTHONNOUSERSITE",
        'distribution_version("phoenix-os") == {version!r}',
        "BUILTIN_AUTHORITY_CATALOG",
        "authority_subject_fingerprint",
        "authority_intent_fingerprint",
        "UnknownAuthorityOperationError",
        '"-I"',
    ):
        assert phrase in text


def test_authority_release_gate_is_last_named_gate_in_ci_local_checks_and_docs() -> None:
    command = "python scripts/check_authority_release.py"
    for path in (_CI, _CHECK_PS1, _CHECK_SH, _README, _RFC):
        assert command in path.read_text(encoding="utf-8")
    for path in (_CI, _CHECK_PS1, _CHECK_SH):
        text = path.read_text(encoding="utf-8")
        assert text.index("python scripts/check_host_automation_release.py") < text.index(command)
