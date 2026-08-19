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
        '"docs/migrations/v0.31.0-to-v0.32.0-secure-host-automation.md"',
        '"docs/adrs/ADR-0060-host-state-is-data-effects-require-fresh-authority.md"',
        '"docs/adrs/ADR-0063-immediate-ui-toctou-revalidation.md"',
        '"scripts/dogfood_host_automation_windows.py"',
        'glob("RFC-0032-*.md")',
        "src/phoenix_os/configuration/dependencies.py",
    ):
        assert phrase in text


def test_host_automation_release_gate_keeps_later_release_gates_separate() -> None:
    text = _GATE.read_text(encoding="utf-8")
    for deferred in (
        '"-m", "build"',
        '"--no-index"',
        "import tarfile",
        "import venv",
        "import zipfile",
        "Windows dogfood",
    ):
        assert deferred not in text


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
    assert "- [ ] Offline wheel/sdist validation" in rfc
    assert "- [ ] Release notes and package version 0.32.0" in rfc
    assert "- [ ] Tag, artifacts, and checksums" in rfc
