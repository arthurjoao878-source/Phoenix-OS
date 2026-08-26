from __future__ import annotations

import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"
_README = _ROOT / "README.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.35.0.md"
_PREVIOUS_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.34.0.md"
_MIGRATION = _ROOT / "docs" / "migrations" / "v0.34.0-to-v0.35.0-secure-browser-automation.md"
_SECURITY = (
    _ROOT / "docs" / "security" / "RFC-0035-secure-browser-automation-threat-model-review.md"
)
_RFC = (
    _ROOT / "docs" / "rfcs" / "RFC-0035-secure-browser-automation-and-controlled-web-interaction.md"
)
_GATE = _ROOT / "scripts" / "check_browser_automation_release.py"


def test_project_version_is_v0350() -> None:
    assert tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]["version"] == "0.35.0"


def test_readme_announces_thirty_five_specs_and_browser_gate() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "Version `0.35.0` implements thirty-five accepted specifications:" in readme
    assert "RFC-0035" in readme
    assert "Secure Browser Automation and Controlled Web Interaction" in readme
    current = "[Phoenix OS 0.35.0](docs/releases/v0.35.0.md)"
    previous = "[Phoenix OS 0.34.0](docs/releases/v0.34.0.md)"
    assert readme.count(current) == 1 and readme.index(current) < readme.index(previous)
    assert "## Browser-automation release gate" in readme
    assert "python scripts/check_browser_automation_release.py" in readme


def test_changelog_starts_with_v0350_release() -> None:
    changelog = _CHANGELOG.read_text(encoding="utf-8")
    current = "## [0.35.0] - 2026-08-26"
    previous = "## [0.34.0] - 2026-08-24"
    assert changelog.count(current) == 1 and changelog.index(current) < changelog.index(previous)
    for phrase in (
        "Accepted RFC-0035 secure browser automation and controlled web interaction",
        "Web content is data",
        "browser.page.read",
        "INDETERMINATE",
        "zero-effect",
        "browser.health.read",
        "isolated offline",
    ):
        assert phrase.lower() in changelog.lower()


def test_v035_release_notes_and_migration_are_complete() -> None:
    notes = _RELEASE_NOTES.read_text(encoding="utf-8")
    for phrase in (
        "# Phoenix OS 0.35.0",
        "**Released:** 2026-08-26",
        "## Highlights",
        "## Security",
        "## Compatibility and migration",
        "## Release validation",
        "## Artifacts",
        "python scripts/check_browser_automation_release.py",
        "annotated Git tag `v0.35.0`",
        "phoenix_os-0.35.0-py3-none-any.whl",
        "phoenix_os-0.35.0.tar.gz",
        "SHA256SUMS",
        "INDETERMINATE",
        "browser.page.read",
    ):
        assert phrase in notes
    assert "TODO" not in notes.upper() and "TBD" not in notes.upper()

    migration = _MIGRATION.read_text(encoding="utf-8")
    for phrase in (
        "# Migration: Phoenix OS v0.34.0 to v0.35.0 secure browser automation",
        "browser.page.read",
        "tool.invoke",
        "verified HTTPS",
        "zero-effect",
        "INDETERMINATE",
        "browser.health.read",
        "python scripts/check_browser_automation_release.py",
    ):
        assert phrase in migration


def test_security_review_and_rfc_are_release_complete() -> None:
    assert _SECURITY.is_file()
    security = _SECURITY.read_text(encoding="utf-8")
    assert "Phoenix OS 0.35.0 release candidate" in security
    assert "release metadata finalization plus" in security
    assert "compatibility-only release-gate wiring did not" in security
    assert (
        "runtime behavior, package authority, browser semantics, or network semantics" in security
    )

    rfc = _RFC.read_text(encoding="utf-8")
    normalized = " ".join(rfc.split())
    assert "- Status: Accepted" in rfc and "- [ ]" not in rfc
    assert (
        "RFC-0035 is accepted for Phoenix OS 0.35.0 after the complete regression suite"
        in normalized
    )
    assert "python scripts/check_browser_automation_release.py" in rfc
    assert "Annotated tag publication" in rfc


def test_browser_gate_and_previous_release_notes_remain_available() -> None:
    assert _GATE.is_file() and _PREVIOUS_RELEASE_NOTES.is_file()
    assert "# Phoenix OS 0.34.0" in _PREVIOUS_RELEASE_NOTES.read_text(encoding="utf-8")
