from __future__ import annotations

import re
import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"
_README = _ROOT / "README.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_RELEASE = _ROOT / "docs" / "releases" / "v0.39.0.md"
_MIGRATION = (
    _ROOT
    / "docs"
    / "migrations"
    / "v0.38.0-to-v0.39.0-usable-real-task-operation-and-controlled-workspace-mutation.md"
)
_RFC = (
    _ROOT
    / "docs"
    / "rfcs"
    / "RFC-0039-usable-real-task-operation-and-controlled-workspace-mutation.md"
)
_DOGFOOD = _ROOT / "docs" / "rfcs" / "RFC-0039-real-provider-dogfood-checklist.md"


def _dogfood_states(text: str) -> list[str]:
    section = text.split("## Required real workload evidence", 1)[1].split(
        "## Recommended normal-task sample", 1
    )[0]
    return [
        "x" if state.lower() == "x" else " "
        for state in re.findall(r"(?m)^\s*-\s+\[([ xX])\]\s+", section)
    ]


def test_v039_candidate_package_and_docs_contract() -> None:
    project = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]
    assert project["version"] == "0.39.0"
    assert project["dependencies"] == []

    readme = _README.read_text(encoding="utf-8")
    assert "Version `0.39.0` release-candidate metadata" in readme
    assert "RFC-0039 - Usable Real-Task Operation and Controlled Workspace Mutation" in readme
    assert "[Phoenix OS 0.39.0](docs/releases/v0.39.0.md)" in readme
    assert "RFC-0039 remains Proposed" in readme

    changelog = _CHANGELOG.read_text(encoding="utf-8")
    assert "## [0.39.0] - Unreleased" in changelog
    assert "RFC-0039 remains Proposed" in changelog
    assert "controlled `workspace.patch`" in changelog
    assert "Ordinary CI remains deterministic and network-free" in changelog


def test_v039_candidate_release_notes_are_pending_not_published() -> None:
    release = _RELEASE.read_text(encoding="utf-8")
    assert "**Release candidate prepared:** 2026-09-13" in release
    assert "**Publication:** pending" in release
    assert "**Released:**" not in release
    assert "RFC-0039 remains Proposed" in release
    assert "No publication artifact" in release
    for heading in (
        "## Security",
        "## Compatibility and migration",
        "## Dogfood and operations",
        "## Release validation",
        "## Artifacts",
    ):
        assert heading in release


def test_v039_migration_preserves_fail_closed_authority_model() -> None:
    migration = _MIGRATION.read_text(encoding="utf-8")
    migration_flat = " ".join(migration.split())
    for phrase in (
        "No migration action is required",
        "The normal path must not depend on a task-specific or custom Python composition helper.",
        "`workspace.list`",
        "`workspace.read`",
        "Trusted review presents the bounded exact diff.",
        "Indeterminate effects are not blindly replayed.",
        "Ordinary CI stays deterministic and",
        "network-free.",
    ):
        assert phrase in migration_flat


def test_rfc0039_is_still_proposed_until_final_gate_and_dogfood() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- Status: Proposed" in rfc
    assert "- Target release: Phoenix OS v0.39.0" in rfc
    assert "Real-provider dogfood remains separately invoked" in rfc
    assert "official candidate wheel installed into a clean virtual environment" in rfc
    assert "No custom Python composition helper may be used" in rfc
    assert "The final v0.39 release gate must include:" in rfc
    assert "RFC-0039 may move from Proposed to Accepted only when" in rfc


def test_v039_real_provider_dogfood_remains_open() -> None:
    dogfood = _DOGFOOD.read_text(encoding="utf-8")
    states = _dogfood_states(dogfood)
    assert states == [" "] * 20
    assert "official v0.39 candidate wheel" in dogfood
    assert "Do not use a custom Python composition helper." in dogfood
    assert "No shell or Git authority is used." in dogfood
    assert "Completing this checklist does not by itself authorize" in dogfood
