from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_README = _ROOT / "README.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.36.0.md"
_PREVIOUS_RELEASE_NOTES = _ROOT / "docs" / "releases" / "v0.35.0.md"
_MIGRATION = (
    _ROOT / "docs" / "migrations" / "v0.35.0-to-v0.36.0-secure-integrated-agent-execution.md"
)
_SECURITY = (
    _ROOT
    / "docs"
    / "security"
    / "RFC-0036-secure-integrated-agent-execution-threat-model-review.md"
)
_RFC = (
    _ROOT
    / "docs"
    / "rfcs"
    / "RFC-0036-secure-integrated-agent-execution-and-end-to-end-orchestration.md"
)
_GATE = _ROOT / "scripts" / "check_integrated_agent_release.py"


def test_readme_preserves_v036_release_history_and_integrated_gate() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "RFC-0036" in readme
    assert "Secure Integrated Agent Execution and End-to-End Orchestration" in readme
    current = "[Phoenix OS 0.36.0](docs/releases/v0.36.0.md)"
    previous = "[Phoenix OS 0.35.0](docs/releases/v0.35.0.md)"
    assert readme.count(current) == 1 and readme.index(current) < readme.index(previous)
    assert "## Integrated-agent release gate" in readme
    assert "python scripts/check_integrated_agent_release.py" in readme


def test_changelog_starts_with_v0360_release() -> None:
    changelog = _CHANGELOG.read_text(encoding="utf-8")
    current = "## [0.36.0] - 2026-08-28"
    previous = "## [0.35.0] - 2026-08-26"
    assert changelog.count(current) == 1 and changelog.index(current) < changelog.index(previous)
    for phrase in (
        "Accepted RFC-0036 secure integrated agent execution",
        "Planning and content are data",
        "integrated.plan.update",
        "USER_RESULT",
        "INDETERMINATE",
        "integrated.agent.inspection.read",
        "isolated offline",
    ):
        assert phrase.lower() in changelog.lower()


def test_v036_release_notes_and_migration_are_complete() -> None:
    notes = _RELEASE_NOTES.read_text(encoding="utf-8")
    for phrase in (
        "# Phoenix OS 0.36.0",
        "**Released:** 2026-08-28",
        "## Highlights",
        "## Security",
        "## Compatibility and migration",
        "## Release validation",
        "## Artifacts",
        "python scripts/check_integrated_agent_release.py",
        "annotated Git tag `v0.36.0`",
        "phoenix_os-0.36.0-py3-none-any.whl",
        "phoenix_os-0.36.0.tar.gz",
        "SHA256SUMS",
        "integrated.plan.update",
        "USER_RESULT",
        "INDETERMINATE",
        "integrated.agent.inspection.read",
    ):
        assert phrase in notes
    assert "TODO" not in notes.upper() and "TBD" not in notes.upper()

    migration = _MIGRATION.read_text(encoding="utf-8")
    for phrase in (
        "# Migration: Phoenix OS v0.35.0 to v0.36.0 secure integrated agent execution",
        "IntegratedTaskId",
        "integrated.plan.update",
        "tool.invoke",
        "USER_RESULT",
        "INDETERMINATE",
        "integrated.agent.health.read",
        "integrated.agent.inspection.read",
        "python scripts/check_integrated_agent_release.py",
    ):
        assert phrase in migration


def test_security_review_and_rfc_are_release_complete() -> None:
    assert _SECURITY.is_file()
    security = _SECURITY.read_text(encoding="utf-8")
    normalized_security = " ".join(security.split())
    assert "Phoenix OS 0.36.0 release candidate" in normalized_security
    assert (
        "release metadata finalization plus compatibility-only release-gate wiring did not"
        in normalized_security
    )
    assert (
        "runtime behavior, package authority, integrated execution semantics, or downstream "
        "authority semantics" in normalized_security
    )

    rfc = _RFC.read_text(encoding="utf-8")
    normalized = " ".join(rfc.split())
    assert "- Status: Accepted" in rfc and "- [ ]" not in rfc
    assert (
        "RFC-0036 is accepted for Phoenix OS 0.36.0 after the complete regression suite"
        in normalized
    )
    assert "python scripts/check_integrated_agent_release.py" in rfc
    assert "Annotated tag publication" in rfc


def test_integrated_gate_and_previous_release_notes_remain_available() -> None:
    assert _GATE.is_file() and _PREVIOUS_RELEASE_NOTES.is_file()
    assert "# Phoenix OS 0.35.0" in _PREVIOUS_RELEASE_NOTES.read_text(encoding="utf-8")
