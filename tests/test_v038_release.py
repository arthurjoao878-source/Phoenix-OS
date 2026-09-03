from __future__ import annotations

import re
import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"
_README = _ROOT / "README.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_RELEASE = _ROOT / "docs" / "releases" / "v0.38.0.md"
_MIGRATION = _ROOT / "docs" / "migrations" / "v0.37.0-to-v0.38.0-real-provider-dogfood.md"
_RFC = (
    _ROOT
    / "docs"
    / "rfcs"
    / "RFC-0038-secure-real-model-provider-execution-and-integrated-agent-dogfood.md"
)
_DOGFOOD = _ROOT / "docs" / "rfcs" / "RFC-0038-real-provider-dogfood-checklist.md"


def _slice7_states(text: str) -> list[str]:
    section = text.split("### Slice 7 - v0.38.0 release gate and finalization", 1)[1].split(
        "## Acceptance criteria", 1
    )[0]
    return [
        "x" if state.lower() == "x" else " "
        for state in re.findall(r"(?m)^\s*-\s+\[([ xX])\]\s+", section)
    ]


def _required_dogfood_states(text: str) -> list[str]:
    section = text.split("## Required real workload evidence", 1)[1].split(
        "## Deliberate failure matrix", 1
    )[0]
    return [
        "x" if state.lower() == "x" else " "
        for state in re.findall(r"(?m)^\s*-\s+\[([ xX])\]\s+", section)
    ]


def test_v038_package_and_docs_contract() -> None:
    project = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]
    assert project["version"] == "0.38.0"
    assert project["dependencies"] == []

    readme = _README.read_text(encoding="utf-8")
    assert "Version `0.38.0` implements thirty-eight accepted specifications:" in readme
    assert "Secure Real-Model Provider Execution and Integrated Agent Dogfood" in readme
    assert "[Phoenix OS 0.38.0](docs/releases/v0.38.0.md)" in readme
    assert "There is no automatic local-to-cloud fallback." in readme

    changelog = _CHANGELOG.read_text(encoding="utf-8")
    assert "## [0.38.0] - 2026-09-03" in changelog
    assert "Accepted RFC-0038" in changelog
    assert "no automatic local-to-cloud fallback" in changelog
    assert "no transparent retry" in changelog
    assert "content-free real-provider dogfood evidence" in changelog


def test_v038_acceptance_and_publication_boundary() -> None:
    release = _RELEASE.read_text(encoding="utf-8")
    assert "**Release candidate finalized:** 2026-09-03" in release
    assert "**Publication:** pending" in release
    assert "**Released:**" not in release
    assert "Phoenix OS 0.38.0 accepts RFC-0038" in release
    for heading in (
        "## Security",
        "## Compatibility and migration",
        "## Dogfood and operations",
        "## Release validation",
        "## Artifacts",
    ):
        assert heading in release

    migration = _MIGRATION.read_text(encoding="utf-8")
    assert "There is no automatic local-to-cloud fallback." in migration
    assert "must not be transparently replayed" in migration
    assert "## Dogfood guidance" in migration
    assert "## Rollback guidance" in migration
    assert "Mandatory CI remains deterministic and network-free." in migration

    rfc = _RFC.read_text(encoding="utf-8")
    assert "- Status: Accepted" in rfc
    assert "- Architecture freeze: 2026-09-03" in rfc
    assert _slice7_states(rfc) == ["x"] * 11 + [" "]
    assert "## Acceptance" in rfc
    assert "RFC-0038 is accepted for Phoenix OS v0.38.0" in rfc
    assert "Tagging and publication remain separate explicitly authorized operations." in rfc


def test_v038_real_dogfood_evidence_is_closed() -> None:
    dogfood = _DOGFOOD.read_text(encoding="utf-8")
    assert _required_dogfood_states(dogfood) == ["x"] * 14
