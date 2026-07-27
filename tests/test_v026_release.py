from __future__ import annotations

import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"
_README = _ROOT / "README.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.26.0.md"
_PREVIOUS_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.25.0.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0026-secure-model-providers-and-inference-runtime.md"
_GATE = _ROOT / "scripts" / "check_inference_release.py"


def test_project_version_is_v0260() -> None:
    document = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    assert document["project"]["version"] == "0.26.0"


def test_readme_announces_twenty_six_accepted_specifications() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "Version `0.26.0` implements twenty-six accepted specifications:" in readme
    assert "**RFC-0026 — Secure Model Providers and Inference Runtime:**" in readme
    assert "## Draft specifications" not in readme
    assert "[Phoenix OS 0.26.0](docs/releases/v0.26.0.md)" in readme
    assert "[Phoenix OS 0.25.0](docs/releases/v0.25.0.md)" in readme


def test_changelog_starts_with_v0260_release() -> None:
    changelog = _CHANGELOG.read_text(encoding="utf-8")
    current = "## [0.26.0] - 2026-07-27"
    previous = "## [0.25.0] - 2026-07-25"
    assert changelog.count(current) == 1
    assert changelog.index(current) < changelog.index(previous)
    assert "Accepted RFC-0026" in changelog
    assert "disabled by default" in changelog
    assert "Model output remains untrusted" in changelog
    assert "isolated offline" in changelog


def test_release_notes_are_complete() -> None:
    notes = _RELEASE_NOTES.read_text(encoding="utf-8")
    required = (
        "# Phoenix OS 0.26.0",
        "**Released:** 2026-07-27",
        "## Highlights",
        "## Security",
        "## Compatibility and migration",
        "## Architecture decisions",
        "## Release validation",
        "## Artifacts",
        "python scripts/check_webhook_release.py",
        "python scripts/check_inbound_release.py",
        "python scripts/check_inference_release.py",
        "Git tag `v0.26.0`",
        "phoenix_os-0.26.0-py3-none-any.whl",
        "phoenix_os-0.26.0.tar.gz",
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
    assert "Inference is disabled by default" in notes
    assert "Model output is untrusted data" in notes
    assert "receive no inference scopes or model resources automatically" in notes
    assert "Prompts, responses, credentials, endpoint details" in notes
    assert "separate from model invocation authority" in notes
    assert "v0.25.0-to-v0.26.0-inference.md" in notes


def test_rfc_is_fully_accepted_for_v0260() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- Status: Accepted" in rfc
    assert "- [ ]" not in rfc
    assert "- [x] Release notes, version 0.26.0, tag, artifacts, and checksums" in rfc
    assert "RFC-0026 is accepted for Phoenix OS 0.26.0." in rfc
    assert "docs/releases/v0.26.0.md" in rfc


def test_inference_release_gate_includes_release_metadata() -> None:
    gate = _GATE.read_text(encoding="utf-8")
    for phrase in (
        '"tests/test_v026_release.py"',
        '"CHANGELOG.md"',
        '"docs/releases/v0.26.0.md"',
    ):
        assert phrase in gate


def test_primary_metadata_has_no_stale_current_version() -> None:
    pyproject = _PYPROJECT.read_text(encoding="utf-8")
    readme = _README.read_text(encoding="utf-8")
    assert 'version = "0.25.0"' not in pyproject
    assert "Version `0.25.0` implements" not in readme


def test_previous_release_notes_remain_available() -> None:
    assert _PREVIOUS_RELEASE_NOTES.is_file()
    previous = _PREVIOUS_RELEASE_NOTES.read_text(encoding="utf-8")
    assert "# Phoenix OS 0.25.0" in previous
    assert "RFC-0025" in previous
