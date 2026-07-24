from __future__ import annotations

import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"
_README = _ROOT / "README.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.24.0.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0024-durable-signed-webhooks-and-event-subscriptions.md"
_GATE = _ROOT / "scripts" / "check_webhook_release.py"


def test_project_version_is_v0240() -> None:
    document = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    assert document["project"]["version"] == "0.24.0"


def test_readme_announces_twenty_four_accepted_specifications() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "Version `0.24.0` implements twenty-four accepted specifications:" in readme
    assert "**RFC-0024 — Durable Signed Webhooks and Event Subscriptions:**" in readme
    assert "[Phoenix OS 0.24.0](docs/releases/v0.24.0.md)" in readme


def test_changelog_starts_with_v0240_release() -> None:
    changelog = _CHANGELOG.read_text(encoding="utf-8")
    current = "## [0.24.0] - 2026-07-24"
    previous = "## [0.23.0] - 2026-07-21"
    assert changelog.count(current) == 1
    assert changelog.index(current) < changelog.index(previous)
    assert "Accepted RFC-0024" in changelog
    assert "disabled by default" in changelog
    assert "DNS rebinding" in changelog


def test_release_notes_are_complete() -> None:
    notes = _RELEASE_NOTES.read_text(encoding="utf-8")
    required = (
        "# Phoenix OS 0.24.0",
        "**Released:** 2026-07-24",
        "## Highlights",
        "## Security",
        "## Compatibility and migration",
        "## Architecture decisions",
        "## Release validation",
        "## Artifacts",
        "python scripts/check_webhook_release.py",
        "phoenix_os-0.24.0-py3-none-any.whl",
        "phoenix_os-0.24.0.tar.gz",
    )
    for phrase in required:
        assert phrase in notes
    upper = notes.upper()
    assert "TODO" not in upper
    assert "TBD" not in upper
    assert "UNRELEASED" not in upper


def test_release_notes_preserve_compatibility_boundary() -> None:
    notes = _RELEASE_NOTES.read_text(encoding="utf-8")
    assert "disabled by default" in notes
    assert "Existing Event Bus subscribers are not converted" in notes
    assert "No signing key" in notes
    assert "outbound permission is created automatically" in notes
    assert "v0.23.0-to-v0.24.0-webhooks.md" in notes


def test_rfc_is_fully_accepted_for_v0240() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- [ ]" not in rfc
    assert "- [x] Release notes and version 0.24.0" in rfc
    assert "RFC-0024 is accepted for Phoenix OS 0.24.0." in rfc
    assert "docs/releases/v0.24.0.md" in rfc


def test_release_gate_includes_release_metadata() -> None:
    gate = _GATE.read_text(encoding="utf-8")
    for phrase in (
        '"tests/test_v024_release.py"',
        '"CHANGELOG.md"',
        '"docs/releases/v0.24.0.md"',
    ):
        assert phrase in gate


def test_primary_metadata_has_no_stale_version() -> None:
    pyproject = _PYPROJECT.read_text(encoding="utf-8")
    readme = _README.read_text(encoding="utf-8")
    assert 'version = "0.23.0"' not in pyproject
    assert "Version `0.23.0` implements" not in readme
