from __future__ import annotations

import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"
_README = _ROOT / "README.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.30.0.md"
_PREVIOUS_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.29.0.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0030-secure-agent-memory-and-context-retrieval.md"
_GATE = _ROOT / "scripts" / "check_agent_memory_release.py"


def test_project_version_is_v0300() -> None:
    document = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    assert document["project"]["version"] == "0.30.0"


def test_readme_announces_thirty_specs_and_agent_memory_gate() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "Version `0.30.0` implements thirty accepted specifications:" in readme
    assert "**RFC-0030 — Secure Agent Memory and Context Retrieval:**" in readme
    current = "[Phoenix OS 0.30.0](docs/releases/v0.30.0.md)"
    previous = "[Phoenix OS 0.29.0](docs/releases/v0.29.0.md)"
    assert readme.count(current) == 1
    assert readme.index(current) < readme.index(previous)
    assert "## Agent-memory release gate" in readme


def test_changelog_starts_with_v0300_release_candidate() -> None:
    changelog = _CHANGELOG.read_text(encoding="utf-8")
    current = "## [0.30.0] - 2026-08-12"
    previous = "## [0.29.0] - 2026-08-11"
    assert changelog.count(current) == 1
    assert changelog.index(current) < changelog.index(previous)
    for phrase in (
        "RFC-0030",
        "Memory informs work, never authority",
        "memory.search",
        "MemoryContextBlock",
        "tombstone",
        "semantic",
        "isolated offline",
    ):
        assert phrase in changelog


def test_v030_release_candidate_notes_are_complete() -> None:
    notes = _RELEASE_NOTES.read_text(encoding="utf-8")
    for phrase in (
        "# Phoenix OS 0.30.0",
        "**Release candidate:** 2026-08-12",
        "## Highlights",
        "## Security",
        "## Compatibility and migration",
        "## Architecture decisions",
        "## Release validation",
        "## Planned artifacts",
        "python scripts/check_agent_memory_release.py",
        "Git tag `v0.30.0`",
        "phoenix_os-0.30.0-py3-none-any.whl",
        "phoenix_os-0.30.0.tar.gz",
        "SHA256SUMS",
    ):
        assert phrase in notes
    upper = notes.upper()
    assert "TODO" not in upper
    assert "TBD" not in upper


def test_rfc_remains_draft_until_publication_artifacts_exist() -> None:
    rfc = " ".join(_RFC.read_text(encoding="utf-8").split())
    assert "- Status: Draft" in rfc
    assert "- [ ] Tag, artifacts, and checksums" in rfc
    assert "- Target release: Phoenix OS v0.30.0" in rfc


def test_gate_and_previous_release_notes_remain_available() -> None:
    assert _GATE.is_file()
    assert _PREVIOUS_RELEASE_NOTES.is_file()
    assert "# Phoenix OS 0.29.0" in _PREVIOUS_RELEASE_NOTES.read_text(encoding="utf-8")
