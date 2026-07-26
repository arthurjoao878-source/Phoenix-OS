from __future__ import annotations

import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"
_README = _ROOT / "README.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.25.0.md"
_PREVIOUS_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.24.0.md"
_RFC = (
    _ROOT / "docs" / "rfcs" / "RFC-0025-secure-inbound-event-gateway-and-external-event-sources.md"
)
_GATE = _ROOT / "scripts" / "check_inbound_release.py"


def test_project_version_is_v0250() -> None:
    document = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    assert document["project"]["version"] == "0.25.0"


def test_readme_announces_twenty_five_accepted_specifications() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "Version `0.25.0` implements twenty-five accepted specifications:" in readme
    assert "**RFC-0025 — Secure Inbound Event Gateway and External Event Sources:**" in readme
    assert "## Draft specifications" in readme
    assert (
        "[RFC-0026 — Secure Model Providers and Inference Runtime]"
        "(docs/rfcs/RFC-0026-secure-model-providers-and-inference-runtime.md)" in readme
    )
    assert "[Phoenix OS 0.25.0](docs/releases/v0.25.0.md)" in readme
    assert "[Phoenix OS 0.24.0](docs/releases/v0.24.0.md)" in readme


def test_changelog_starts_with_v0250_release() -> None:
    changelog = _CHANGELOG.read_text(encoding="utf-8")
    current = "## [0.25.0] - 2026-07-25"
    previous = "## [0.24.0] - 2026-07-24"
    assert changelog.count(current) == 1
    assert changelog.index(current) < changelog.index(previous)
    assert "Accepted RFC-0025" in changelog
    assert "disabled by default" in changelog
    assert "Raw request bodies" in changelog
    assert "isolated offline" in changelog


def test_release_notes_are_complete() -> None:
    notes = _RELEASE_NOTES.read_text(encoding="utf-8")
    required = (
        "# Phoenix OS 0.25.0",
        "**Released:** 2026-07-25",
        "## Highlights",
        "## Security",
        "## Compatibility and migration",
        "## Architecture decisions",
        "## Release validation",
        "## Artifacts",
        "python scripts/check_webhook_release.py",
        "python scripts/check_inbound_release.py",
        "phoenix_os-0.25.0-py3-none-any.whl",
        "phoenix_os-0.25.0.tar.gz",
        "SHA256SUMS",
    )
    for phrase in required:
        assert phrase in notes
    upper = notes.upper()
    assert "TODO" not in upper
    assert "TBD" not in upper
    assert "UNRELEASED" not in upper


def test_release_notes_preserve_compatibility_and_authority_boundaries() -> None:
    notes = _RELEASE_NOTES.read_text(encoding="utf-8")
    assert "disabled by default" in notes
    assert "Existing webhook subscriptions are not converted" in notes
    assert "receive no inbound scopes or source resources automatically" in notes
    assert "Raw request bodies are never published directly" in notes
    assert "independent exact permissions" in notes
    assert "v0.24.0-to-v0.25.0-inbound-events.md" in notes


def test_rfc_is_fully_accepted_for_v0250() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- Status: Accepted" in rfc
    assert "- [ ]" not in rfc
    assert "- [x] Release notes and version 0.25.0" in rfc
    assert "RFC-0025 is accepted for Phoenix OS 0.25.0." in rfc
    assert "docs/releases/v0.25.0.md" in rfc


def test_inbound_release_gate_includes_release_metadata() -> None:
    gate = _GATE.read_text(encoding="utf-8")
    for phrase in (
        '"tests/test_v025_release.py"',
        '"CHANGELOG.md"',
        '"docs/releases/v0.25.0.md"',
    ):
        assert phrase in gate


def test_primary_metadata_has_no_stale_current_version() -> None:
    pyproject = _PYPROJECT.read_text(encoding="utf-8")
    readme = _README.read_text(encoding="utf-8")
    assert 'version = "0.24.0"' not in pyproject
    assert "Version `0.24.0` implements" not in readme


def test_previous_release_notes_remain_available() -> None:
    assert _PREVIOUS_RELEASE_NOTES.is_file()
    previous = _PREVIOUS_RELEASE_NOTES.read_text(encoding="utf-8")
    assert "# Phoenix OS 0.24.0" in previous
    assert "RFC-0024" in previous
