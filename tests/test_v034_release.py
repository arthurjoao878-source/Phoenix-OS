from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_README = _ROOT / "README.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.34.0.md"
_PREVIOUS_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.33.0.md"
_MIGRATION = _ROOT / "docs" / "migrations" / "v0.33.0-to-v0.34.0-secure-network-egress.md"
_SECURITY = _ROOT / "docs" / "security" / "RFC-0034-secure-network-egress-threat-model-review.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0034-secure-network-egress-and-controlled-http-operations.md"
_GATE = _ROOT / "scripts" / "check_network_egress_release.py"


def test_v034_release_history_remains_available() -> None:
    assert _RELEASE_NOTES.is_file()
    assert "# Phoenix OS 0.34.0" in _RELEASE_NOTES.read_text(encoding="utf-8")
    assert "## [0.34.0] - 2026-08-24" in _CHANGELOG.read_text(encoding="utf-8")


def test_readme_preserves_v034_release_history_and_network_gate() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "RFC-0034" in readme
    assert "Secure Network Egress and Controlled HTTP Operations" in readme
    current = "[Phoenix OS 0.34.0](docs/releases/v0.34.0.md)"
    previous = "[Phoenix OS 0.33.0](docs/releases/v0.33.0.md)"
    assert readme.count(current) == 1 and readme.index(current) < readme.index(previous)
    assert "## Network-egress release gate" in readme


def test_changelog_starts_with_v0340_release() -> None:
    changelog = _CHANGELOG.read_text(encoding="utf-8")
    current = "## [0.34.0] - 2026-08-24"
    previous = "## [0.33.0] - 2026-08-23"
    assert changelog.count(current) == 1 and changelog.index(current) < changelog.index(previous)
    for phrase in (
        "Accepted RFC-0034 secure network egress and controlled HTTP operations",
        "Remote data is data",
        "network.http.request",
        "SSRF",
        "DNS-rebinding",
        "indeterminate",
        "isolated offline",
    ):
        assert phrase.lower() in changelog.lower()


def test_v034_release_notes_and_migration_are_complete() -> None:
    notes = _RELEASE_NOTES.read_text(encoding="utf-8")
    for phrase in (
        "# Phoenix OS 0.34.0",
        "**Released:** 2026-08-24",
        "## Highlights",
        "## Security",
        "## Compatibility and migration",
        "## Release validation",
        "## Artifacts",
        "python scripts/check_network_egress_release.py",
        "annotated Git tag `v0.34.0`",
        "phoenix_os-0.34.0-py3-none-any.whl",
        "phoenix_os-0.34.0.tar.gz",
        "SHA256SUMS",
    ):
        assert phrase in notes
    assert "TODO" not in notes.upper() and "TBD" not in notes.upper()
    migration = _MIGRATION.read_text(encoding="utf-8")
    for phrase in (
        "# Migrating Phoenix OS 0.33.0 to 0.34.0",
        "network.http.request",
        "tool.invoke",
        "verified HTTPS",
        "Redirects are not followed",
        "indeterminate",
        "Rollback",
        "python scripts/check_network_egress_release.py",
    ):
        assert phrase in migration


def test_security_review_and_rfc_are_release_complete() -> None:
    assert _SECURITY.is_file()
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- Status: Accepted" in rfc and "- [ ]" not in rfc
    assert (
        "RFC-0034 is accepted for Phoenix OS 0.34.0 after the complete regression suite"
        in " ".join(rfc.split())
    )
    assert "python scripts/check_network_egress_release.py" in rfc


def test_network_gate_and_previous_release_notes_remain_available() -> None:
    assert _GATE.is_file() and _PREVIOUS_RELEASE_NOTES.is_file()
    assert "# Phoenix OS 0.33.0" in _PREVIOUS_RELEASE_NOTES.read_text(encoding="utf-8")
