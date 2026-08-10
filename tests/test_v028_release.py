from __future__ import annotations

import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"
_README = _ROOT / "README.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.28.0.md"
_PREVIOUS_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.27.0.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0028-durable-agent-runs-and-controlled-resumption.md"
_GATE = _ROOT / "scripts" / "check_durable_agent_release.py"


def test_project_version_is_v0280() -> None:
    document = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    assert document["project"]["version"] == "0.28.0"


def test_readme_lists_v028_release_notes_before_v027() -> None:
    readme = _README.read_text(encoding="utf-8")
    current = "[Phoenix OS 0.28.0](docs/releases/v0.28.0.md)"
    previous = "[Phoenix OS 0.27.0](docs/releases/v0.27.0.md)"
    assert readme.count(current) == 1
    assert readme.index(current) < readme.index(previous)


def test_changelog_starts_with_v0280_release_candidate() -> None:
    changelog = _CHANGELOG.read_text(encoding="utf-8")
    current = "## [0.28.0] - 2026-08-10"
    previous = "## [0.27.0] - 2026-07-29"
    assert changelog.count(current) == 1
    assert changelog.index(current) < changelog.index(previous)
    for phrase in (
        "RFC-0028",
        "checkpoint",
        "fencing",
        "indeterminate",
        "protected payload",
        "isolated offline",
    ):
        assert phrase in changelog


def test_v028_release_notes_are_complete() -> None:
    notes = _RELEASE_NOTES.read_text(encoding="utf-8")
    required = (
        "# Phoenix OS 0.28.0",
        "**Prepared:** 2026-08-10",
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
        "python scripts/check_durable_agent_release.py",
        "Git tag `v0.28.0`",
        "phoenix_os-0.28.0-py3-none-any.whl",
        "phoenix_os-0.28.0.tar.gz",
        "SHA256SUMS",
    )
    for phrase in required:
        assert phrase in notes
    upper = notes.upper()
    assert "TODO" not in upper
    assert "TBD" not in upper
    assert "UNRELEASED" not in upper


def test_v028_release_notes_preserve_security_boundaries() -> None:
    notes = " ".join(_RELEASE_NOTES.read_text(encoding="utf-8").split())
    for phrase in (
        "A checkpoint is data, not authority",
        "Stale workers cannot mutate after lease replacement",
        "no transparent retry of an indeterminate model or tool attempt",
        "does not claim exactly-once external side effects",
        "Protected content is absent by default",
        "Plaintext prompts, responses, raw arguments, results",
        "RFC-0028 is not a hostile code sandbox",
        "v0.27.0 to v0.28.0 durable-agent migration guide",
    ):
        assert phrase in notes


def test_rfc_marks_release_metadata_ready_but_publication_pending() -> None:
    rfc = " ".join(_RFC.read_text(encoding="utf-8").split())
    assert "- Status: Draft" in rfc
    assert "- [x] Release notes and package version 0.28.0" in rfc
    assert "- [ ] Tag, artifacts, and checksums" in rfc
    assert "docs/releases/v0.28.0.md" in rfc
    assert "package version is `0.28.0`" in rfc
    assert "RFC-0028 is accepted for Phoenix OS 0.28.0." not in rfc


def test_durable_release_gate_includes_v028_release_metadata() -> None:
    gate = _GATE.read_text(encoding="utf-8")
    for phrase in (
        '"tests/test_v028_release.py"',
        '"CHANGELOG.md"',
        '"docs/releases/v0.28.0.md"',
    ):
        assert phrase in gate


def test_previous_release_notes_remain_available() -> None:
    assert _PREVIOUS_RELEASE_NOTES.is_file()
    previous = _PREVIOUS_RELEASE_NOTES.read_text(encoding="utf-8")
    assert "# Phoenix OS 0.27.0" in previous
    assert "RFC-0027" in previous
