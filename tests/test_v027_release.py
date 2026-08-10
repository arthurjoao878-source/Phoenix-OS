from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"
_README = _ROOT / "README.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.27.0.md"
_PREVIOUS_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.26.0.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0027-secure-agent-loop-and-tool-calling.md"
_GATE = _ROOT / "scripts" / "check_agent_release.py"


def test_v027_release_metadata_remains_available() -> None:
    assert _RELEASE_NOTES.is_file()
    assert _RFC.is_file()


def test_readme_preserves_v027_release_history() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "**RFC-0027 — Secure Agent Loop and Tool Calling Runtime:**" in readme
    assert "[Phoenix OS 0.27.0](docs/releases/v0.27.0.md)" in readme
    assert "[Phoenix OS 0.26.0](docs/releases/v0.26.0.md)" in readme


def test_changelog_starts_with_v0270_release() -> None:
    changelog = _CHANGELOG.read_text(encoding="utf-8")
    current = "## [0.27.0] - 2026-07-29"
    previous = "## [0.26.0] - 2026-07-27"
    assert changelog.count(current) == 1
    assert changelog.index(current) < changelog.index(previous)
    assert "Accepted RFC-0027" in changelog
    assert "disabled by default" in changelog
    assert "Model output and tool results remain untrusted data" in changelog
    assert "isolated package gate" in changelog


def test_release_notes_are_complete() -> None:
    notes = _RELEASE_NOTES.read_text(encoding="utf-8")
    required = (
        "# Phoenix OS 0.27.0",
        "**Released:** 2026-07-29",
        "## Highlights",
        "## Security",
        "## Compatibility and migration",
        "## Architecture decisions",
        "## Release validation",
        "## Artifacts",
        "python scripts/check_webhook_release.py",
        "python scripts/check_inbound_release.py",
        "python scripts/check_inference_release.py",
        "python scripts/check_agent_release.py",
        "Git tag `v0.27.0`",
        "phoenix_os-0.27.0-py3-none-any.whl",
        "phoenix_os-0.27.0.tar.gz",
        "SHA256SUMS",
    )
    for phrase in required:
        assert phrase in notes
    upper = notes.upper()
    assert "TODO" not in upper
    assert "TBD" not in upper
    assert "UNRELEASED" not in upper


def test_release_notes_preserve_security_and_authority_boundaries() -> None:
    notes = " ".join(_RELEASE_NOTES.read_text(encoding="utf-8").split())
    for phrase in (
        "Agent execution is disabled by default",
        "Model output is untrusted data and receives no direct tool authority",
        "every model turn and tool call receives a new independent policy decision",
        "Approvals bind the exact tool, resource, canonical argument digest",
        "performs no transparent retry",
        "Event Bus observations exclude prompts",
        "v0.26.0-to-v0.27.0-agent.md",
    ):
        assert phrase in notes


def test_rfc_is_fully_accepted_for_v0270() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- Status: Accepted" in rfc
    assert "- [ ]" not in rfc
    assert "- [x] Release notes and package version 0.27.0" in rfc
    assert "- [x] Tag, artifacts, and checksums" in rfc
    assert "RFC-0027 is accepted for Phoenix OS 0.27.0." in rfc
    assert "docs/releases/v0.27.0.md" in rfc


def test_agent_release_gate_includes_release_metadata() -> None:
    gate = _GATE.read_text(encoding="utf-8")
    for phrase in (
        '"tests/test_v027_release.py"',
        '"CHANGELOG.md"',
        '"docs/releases/v0.27.0.md"',
    ):
        assert phrase in gate


def test_primary_metadata_has_no_stale_current_version() -> None:
    pyproject = _PYPROJECT.read_text(encoding="utf-8")
    readme = _README.read_text(encoding="utf-8")
    assert 'version = "0.26.0"' not in pyproject
    assert "Version `0.26.0` implements" not in readme


def test_previous_release_notes_remain_available() -> None:
    assert _PREVIOUS_RELEASE_NOTES.is_file()
    previous = _PREVIOUS_RELEASE_NOTES.read_text(encoding="utf-8")
    assert "# Phoenix OS 0.26.0" in previous
    assert "RFC-0026" in previous
