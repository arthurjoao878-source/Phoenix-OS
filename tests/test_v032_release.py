from __future__ import annotations

import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"
_README = _ROOT / "README.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.32.0.md"
_PREVIOUS_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.31.0.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0032-secure-host-automation-and-desktop-control.md"
_GATE = _ROOT / "scripts" / "check_host_automation_release.py"


def test_project_version_is_v0320() -> None:
    document = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    assert document["project"]["version"] == "0.32.0"


def test_readme_announces_thirty_two_specs_and_host_automation_gate() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "Version `0.32.0` implements thirty-two accepted specifications:" in readme
    assert "RFC-0032" in readme
    assert "Secure Host Automation and Desktop Control" in readme
    current = "[Phoenix OS 0.32.0](docs/releases/v0.32.0.md)"
    previous = "[Phoenix OS 0.31.0](docs/releases/v0.31.0.md)"
    assert readme.count(current) == 1
    assert readme.index(current) < readme.index(previous)
    assert "## Host-automation release gate" in readme


def test_changelog_starts_with_v0320_release_candidate() -> None:
    changelog = _CHANGELOG.read_text(encoding="utf-8")
    current = "## [0.32.0] - 2026-08-19"
    previous = "## [0.31.0] - 2026-08-14"
    assert changelog.count(current) == 1
    assert changelog.index(current) < changelog.index(previous)
    for phrase in (
        "RFC-0032 secure host automation and desktop control",
        "Desktop state is data; host effects require fresh authority",
        "host.app.launch",
        "opaque Phoenix process/window identities",
        "Graceful-close-only",
        "bounded Unicode text",
        "isolated offline",
    ):
        assert phrase in changelog
    assert "Accepted RFC-0032" not in changelog


def test_v032_release_candidate_notes_are_complete() -> None:
    notes = _RELEASE_NOTES.read_text(encoding="utf-8")
    for phrase in (
        "# Phoenix OS 0.32.0",
        "**Release candidate:** 2026-08-19",
        "## Highlights",
        "## Security",
        "## Compatibility and migration",
        "## Architecture decisions",
        "## Release validation",
        "## Planned artifacts",
        "Desktop state is data; host effects require fresh authority.",
        "python scripts/check_host_automation_release.py",
        "python scripts/dogfood_host_automation_windows.py --confirm-real-effects",
        "Git tag `v0.32.0`",
        "phoenix_os-0.32.0-py3-none-any.whl",
        "phoenix_os-0.32.0.tar.gz",
        "SHA256SUMS",
    ):
        assert phrase in notes
    upper = notes.upper()
    assert "TODO" not in upper
    assert "TBD" not in upper


def test_rfc_remains_draft_until_publication_artifacts_exist() -> None:
    rfc = " ".join(_RFC.read_text(encoding="utf-8").split())
    assert "- Status: Draft" in rfc
    assert "- [x] Release notes and package version 0.32.0" in rfc
    assert "- [ ] Tag, artifacts, and checksums" in rfc
    assert rfc.count("- [ ]") == 1
    assert "- Target release: Phoenix OS v0.32.0" in rfc
    assert "docs/releases/v0.32.0.md" in rfc


def test_gate_and_previous_release_notes_remain_available() -> None:
    assert _GATE.is_file()
    assert _PREVIOUS_RELEASE_NOTES.is_file()
    assert "# Phoenix OS 0.31.0" in _PREVIOUS_RELEASE_NOTES.read_text(encoding="utf-8")
