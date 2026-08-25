from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_README = _ROOT / "README.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.33.0.md"
_PREVIOUS_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.32.0.md"
_MIGRATION = _ROOT / "docs" / "migrations" / "v0.32.0-to-v0.33.0-effective-authority.md"
_SECURITY = _ROOT / "docs" / "security" / "RFC-0033-effective-authority-threat-model-review.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0033-effective-authority-and-capability-non-amplification.md"
_GATE = _ROOT / "scripts" / "check_authority_release.py"


def test_readme_preserves_v033_release_history() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "RFC-0033" in readme
    assert "Effective Authority and Capability Non-Amplification" in readme
    current = "[Phoenix OS 0.33.0](docs/releases/v0.33.0.md)"
    previous = "[Phoenix OS 0.32.0](docs/releases/v0.32.0.md)"
    assert readme.count(current) == 1
    assert readme.index(current) < readme.index(previous)
    assert "## Effective-authority release gate" in readme


def test_changelog_preserves_v0330_release() -> None:
    changelog = _CHANGELOG.read_text(encoding="utf-8")
    current = "## [0.33.0] - 2026-08-23"
    previous = "## [0.32.0] - 2026-08-19"
    assert changelog.count(current) == 1
    assert changelog.index(current) < changelog.index(previous)
    for phrase in (
        "Accepted RFC-0033 effective authority and capability non-amplification",
        "intersection",
        "closed-world",
        "point-in-time",
        "confused-deputy",
        "cross-agent",
        "isolated offline",
    ):
        assert phrase.lower() in changelog.lower()


def test_v033_release_notes_and_migration_remain_complete() -> None:
    notes = _RELEASE_NOTES.read_text(encoding="utf-8")
    for phrase in (
        "# Phoenix OS 0.33.0",
        "**Released:** 2026-08-23",
        "## Highlights",
        "## Security",
        "## Compatibility and migration",
        "## Release validation",
        "## Artifacts",
        "python scripts/check_authority_release.py",
        "Git tag `v0.33.0`",
        "phoenix_os-0.33.0-py3-none-any.whl",
        "phoenix_os-0.33.0.tar.gz",
        "SHA256SUMS",
    ):
        assert phrase in notes
    assert "TODO" not in notes.upper()
    assert "TBD" not in notes.upper()
    migration = _MIGRATION.read_text(encoding="utf-8")
    for phrase in (
        "# Migrating Phoenix OS 0.32.0 to 0.33.0",
        "structural `session_id`",
        "current authority",
        "rollback",
        "python scripts/check_authority_release.py",
    ):
        assert phrase in migration


def test_v033_security_review_and_rfc_remain_accepted() -> None:
    assert _SECURITY.is_file()
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- Status: Accepted" in rfc
    assert "- [ ]" not in rfc
    assert "RFC-0033 is accepted for Phoenix OS 0.33.0." in rfc


def test_v033_gate_and_previous_release_notes_remain_available() -> None:
    assert _GATE.is_file()
    assert _PREVIOUS_RELEASE_NOTES.is_file()
    assert "# Phoenix OS 0.32.0" in _PREVIOUS_RELEASE_NOTES.read_text(encoding="utf-8")
