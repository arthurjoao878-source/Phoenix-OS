from __future__ import annotations

import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"
_README = _ROOT / "README.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.37.0.md"
_PREVIOUS_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.36.0.md"
_MIGRATION = _ROOT / "docs" / "migrations" / "v0.36.0-to-v0.37.0-durable-recovery-reliability.md"
_SECURITY = (
    _ROOT / "docs" / "security" / "RFC-0037-durable-recovery-reliability-threat-model-review.md"
)
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0037-durable-runs-recovery-and-reliability.md"
_GATE = _ROOT / "scripts" / "check_reliability_release.py"


def test_project_version_is_v0370() -> None:
    assert tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]["version"] == "0.37.0"


def test_readme_announces_thirty_seven_specs_and_reliability_gate() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "Version `0.37.0` implements thirty-seven accepted specifications:" in readme
    assert "RFC-0037" in readme
    assert "Durable Runs, Recovery, and Reliability Hardening" in readme
    current = "[Phoenix OS 0.37.0](docs/releases/v0.37.0.md)"
    previous = "[Phoenix OS 0.36.0](docs/releases/v0.36.0.md)"
    assert readme.count(current) == 1 and readme.index(current) < readme.index(previous)
    assert "## Reliability release gate" in readme
    assert "python scripts/check_reliability_release.py" in readme


def test_changelog_starts_with_v0370_release() -> None:
    changelog = _CHANGELOG.read_text(encoding="utf-8")
    current = "## [0.37.0] - 2026-08-30"
    previous = "## [0.36.0] - 2026-08-28"
    assert changelog.count(current) == 1 and changelog.index(current) < changelog.index(previous)
    for phrase in (
        "Accepted RFC-0037",
        "Recovery is continuation under fresh evidence",
        "restart cannot increase authority",
        "COMMIT_OUTCOME_UNKNOWN",
        "freshness witness",
        "check_reliability_release.py",
        "isolated offline",
    ):
        assert phrase.lower() in changelog.lower()


def test_v037_release_notes_and_migration_are_complete() -> None:
    notes = _RELEASE_NOTES.read_text(encoding="utf-8")
    for phrase in (
        "# Phoenix OS 0.37.0",
        "**Released:** 2026-08-30",
        "## Highlights",
        "## Security",
        "## Compatibility and migration",
        "## Release validation",
        "## Artifacts",
        "python scripts/check_reliability_release.py",
        "annotated Git tag `v0.37.0`",
        "phoenix_os-0.37.0-py3-none-any.whl",
        "phoenix_os-0.37.0.tar.gz",
        "SHA256SUMS",
        "COMMIT_OUTCOME_UNKNOWN",
        "INDETERMINATE",
        "freshness witness",
    ):
        assert phrase in notes
    assert "TODO" not in notes.upper() and "TBD" not in notes.upper()

    migration = _MIGRATION.read_text(encoding="utf-8")
    for phrase in (
        "# Migration: Phoenix OS v0.36.0 to v0.37.0 durable recovery reliability hardening",
        "schema version 5",
        "freshness witness",
        "Restart is continuation under fresh evidence, never replay by assumption.",
        "Do not attempt an in-place schema downgrade",
        "python scripts/check_reliability_release.py",
    ):
        assert phrase in migration


def test_security_review_and_rfc_are_release_complete() -> None:
    security = _SECURITY.read_text(encoding="utf-8")
    normalized_security = " ".join(security.split())
    assert "Phoenix OS 0.37.0 release candidate" in normalized_security
    assert (
        "release metadata finalization plus compatibility-only release-gate wiring did not"
        in normalized_security
    )
    assert (
        "runtime behavior, durable authority, replay semantics, fencing semantics, recovery "
        "semantics, or external-effect semantics" in normalized_security
    )

    rfc = _RFC.read_text(encoding="utf-8")
    normalized_rfc = " ".join(rfc.split())
    assert "- Status: Accepted" in rfc and "- [ ]" not in rfc
    assert (
        "RFC-0037 is accepted for Phoenix OS v0.37.0 after the complete regression suite"
        in normalized_rfc
    )
    assert "python scripts/check_reliability_release.py" in rfc
    assert "Annotated tag publication" in rfc


def test_reliability_gate_and_previous_release_notes_remain_available() -> None:
    assert _GATE.is_file() and _PREVIOUS_RELEASE_NOTES.is_file()
    assert "# Phoenix OS 0.36.0" in _PREVIOUS_RELEASE_NOTES.read_text(encoding="utf-8")
