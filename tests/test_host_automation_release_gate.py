from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_GATE = _ROOT / "scripts" / "check_host_automation_release.py"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_CHECK_PS1 = _ROOT / "scripts" / "check.ps1"
_CHECK_SH = _ROOT / "scripts" / "check.sh"
_README = _ROOT / "README.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0032-secure-host-automation-and-desktop-control.md"


def test_host_automation_release_gate_covers_source_and_release_hardening() -> None:
    text = _GATE.read_text(encoding="utf-8")
    for phrase in (
        'glob("test_host_automation*.py")',
        'glob("*.py")',
        '"tests/test_rfc_0032.py"',
        '"tests/test_host_automation_security_review.py"',
        '"tests/test_host_automation_migration_guidance.py"',
        '"tests/test_host_automation_windows_dogfood.py"',
        '"phoenix_os/host_automation/windows_effects.py"',
        '"docs/rfcs/RFC-0032-secure-host-automation-and-desktop-control.md"',
        '"docs/releases/v0.32.0.md"',
        '"tests/test_v032_release.py"',
        '"docs/migrations/v0.31.0-to-v0.32.0-secure-host-automation.md"',
        '"docs/adrs/ADR-0060-host-state-is-data-effects-require-fresh-authority.md"',
        '"docs/adrs/ADR-0063-immediate-ui-toctou-revalidation.md"',
        '"scripts/dogfood_host_automation_windows.py"',
        'glob("RFC-0032-*.md")',
        "src/phoenix_os/configuration/dependencies.py",
    ):
        assert phrase in text


def test_host_automation_release_gate_builds_validates_and_rebuilds_packages() -> None:
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
        '"docs/security/RFC-0032-host-automation-threat-model-review.md"',
    ):
        assert phrase in text


def test_host_automation_release_gate_uses_offline_isolated_deterministic_smoke() -> None:
    text = _GATE.read_text(encoding="utf-8")
    for phrase in (
        "import venv",
        '"--no-deps"',
        '"--no-index"',
        "PYTHONNOUSERSITE",
        'distribution_version("phoenix-os") == {version!r}',
        "DeterministicHostAutomationAdapter",
        "HostAutomationService(",
        "service.list_processes(",
        "service.write_clipboard(",
        "service.read_clipboard(",
        '"-I"',
    ):
        assert phrase in text
    assert "--confirm-real-effects" not in text


def test_host_automation_release_gate_is_named_in_ci_local_checks_and_docs() -> None:
    command = "python scripts/check_host_automation_release.py"
    for path in (_CI, _CHECK_PS1, _CHECK_SH, _README, _RFC):
        assert command in path.read_text(encoding="utf-8")

    for path in (_CI, _CHECK_PS1, _CHECK_SH):
        text = path.read_text(encoding="utf-8")
        assert text.index("python scripts/check_agent_workspace_release.py") < text.index(command)

    rfc = _RFC.read_text(encoding="utf-8")
    assert "- [x] Named host-automation release gate" in rfc
    assert "- [x] Windows dogfood with real process/window/app/clipboard effects" in rfc
    assert "- [x] Offline wheel/sdist validation" in rfc
    assert "- [x] Release notes and package version 0.32.0" in rfc
    assert "- [ ] Tag, artifacts, and checksums" in rfc
