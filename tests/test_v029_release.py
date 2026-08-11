from __future__ import annotations

import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"
_README = _ROOT / "README.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.29.0.md"
_PREVIOUS_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.28.0.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0029-secure-multi-agent-coordination-and-delegation.md"
_GATE = _ROOT / "scripts" / "check_multi_agent_release.py"


def test_project_version_is_v0290() -> None:
    document = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    assert document["project"]["version"] == "0.29.0"


def test_readme_announces_twenty_nine_specs_and_release_candidate() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "Version `0.29.0` implements twenty-nine accepted specifications:" in readme
    assert "**RFC-0029 — Secure Multi-Agent Coordination and Delegation:**" in readme
    current = "[Phoenix OS 0.29.0](docs/releases/v0.29.0.md)"
    previous = "[Phoenix OS 0.28.0](docs/releases/v0.28.0.md)"
    assert readme.count(current) == 1
    assert readme.index(current) < readme.index(previous)
    assert "## Multi-agent release gate" in readme


def test_changelog_starts_with_v0290_release_candidate() -> None:
    changelog = _CHANGELOG.read_text(encoding="utf-8")
    current = "## [0.29.0] - 2026-08-11"
    previous = "## [0.28.0] - 2026-08-10"
    assert changelog.count(current) == 1
    assert changelog.index(current) < changelog.index(previous)
    for phrase in (
        "RFC-0029",
        "agent.delegate",
        "DelegationId",
        "root budget",
        "indeterminate",
        "isolated offline",
    ):
        assert phrase in changelog


def test_v029_release_candidate_notes_are_complete() -> None:
    notes = _RELEASE_NOTES.read_text(encoding="utf-8")
    for phrase in (
        "# Phoenix OS 0.29.0",
        "**Release candidate:** 2026-08-11",
        "## Highlights",
        "## Security",
        "## Compatibility and migration",
        "## Architecture decisions",
        "## Release validation",
        "## Planned artifacts",
        "python scripts/check_multi_agent_release.py",
        "Git tag `v0.29.0`",
        "phoenix_os-0.29.0-py3-none-any.whl",
        "phoenix_os-0.29.0.tar.gz",
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
    assert "- Target release: Phoenix OS v0.29.0" in rfc


def test_gate_and_previous_release_notes_remain_available() -> None:
    assert _GATE.is_file()
    assert _PREVIOUS_RELEASE_NOTES.is_file()
    assert "# Phoenix OS 0.28.0" in _PREVIOUS_RELEASE_NOTES.read_text(encoding="utf-8")
