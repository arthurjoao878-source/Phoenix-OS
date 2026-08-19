from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_README = _ROOT / "README.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.31.0.md"
_PREVIOUS_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.30.0.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0031-secure-agent-workspaces-and-artifact-handling.md"
_GATE = _ROOT / "scripts" / "check_agent_workspace_release.py"


def test_readme_preserves_v031_release_history() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "RFC-0031" in readme
    assert "Secure Agent Workspaces and Artifact Handling" in readme
    current = "[Phoenix OS 0.31.0](docs/releases/v0.31.0.md)"
    previous = "[Phoenix OS 0.30.0](docs/releases/v0.30.0.md)"
    assert readme.count(current) == 1
    assert readme.index(current) < readme.index(previous)
    assert "## Agent-workspace release gate" in readme


def test_changelog_preserves_v0310_release() -> None:
    changelog = _CHANGELOG.read_text(encoding="utf-8")
    current = "## [0.31.0] - 2026-08-14"
    previous = "## [0.30.0] - 2026-08-12"
    assert changelog.count(current) == 1
    assert changelog.index(current) < changelog.index(previous)
    for phrase in (
        "Accepted RFC-0031 secure agent workspaces",
        "Files carry data, never authority",
        "workspace.import",
        "logical paths",
        "ArtifactContextBlock",
        "tombstones",
        "isolated offline",
    ):
        assert phrase in changelog


def test_v031_release_notes_remain_complete() -> None:
    notes = _RELEASE_NOTES.read_text(encoding="utf-8")
    for phrase in (
        "# Phoenix OS 0.31.0",
        "**Released:** 2026-08-14",
        "## Highlights",
        "## Security",
        "## Compatibility and migration",
        "## Architecture decisions",
        "## Release validation",
        "## Artifacts",
        "python scripts/check_agent_workspace_release.py",
        "Git tag `v0.31.0`",
        "phoenix_os-0.31.0-py3-none-any.whl",
        "phoenix_os-0.31.0.tar.gz",
        "SHA256SUMS",
    ):
        assert phrase in notes
    upper = notes.upper()
    assert "TODO" not in upper
    assert "TBD" not in upper
    assert "write/read/update/delete without source-tree imports" in notes
    assert "Import isolation remains" in notes
    assert "workspace regression suite that runs before packaging" in notes
    assert "The release must pass:" in notes
    assert "security-review, and release suites" in notes
    assert "The GitHub release publishes:" in notes


def test_rfc_remains_accepted_for_v0310() -> None:
    rfc = " ".join(_RFC.read_text(encoding="utf-8").split())
    assert "- Status: Accepted" in rfc
    assert "- [ ]" not in rfc
    assert "- [x] Release notes and package version 0.31.0" in rfc
    assert "- [x] Tag, artifacts, and checksums" in rfc
    assert "- Target release: Phoenix OS v0.31.0" in rfc
    assert "RFC-0031 is accepted for Phoenix OS 0.31.0." in rfc


def test_v031_gate_and_previous_release_notes_remain_available() -> None:
    assert _GATE.is_file()
    assert _PREVIOUS_RELEASE_NOTES.is_file()
    assert "# Phoenix OS 0.30.0" in _PREVIOUS_RELEASE_NOTES.read_text(encoding="utf-8")
