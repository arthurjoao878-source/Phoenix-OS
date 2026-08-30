from __future__ import annotations

import re
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = "python scripts/check_reliability_release.py"
PREVIOUS = "python scripts/check_integrated_agent_release.py"


def _namespace() -> dict[str, object]:
    return runpy.run_path(str(ROOT / "scripts/check_reliability_release.py"))


def test_reliability_release_gate_covers_v037_release_metadata() -> None:
    namespace = _namespace()
    companion = namespace["_COMPANION_TESTS"]
    documents = namespace["_REQUIRED_DOCUMENTS"]
    assert isinstance(companion, tuple)
    assert isinstance(documents, tuple)
    assert companion == ("tests/test_v037_release.py",)
    assert "docs/releases/v0.37.0.md" in documents
    assert (ROOT / "tests/test_v037_release.py").is_file()
    assert (ROOT / "docs/releases/v0.37.0.md").is_file()


def test_reliability_gate_is_wired_after_integrated_gate_everywhere() -> None:
    for relative in (
        "scripts/check.ps1",
        "scripts/check.sh",
        ".github/workflows/ci.yml",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert text.count(GATE) == 1
        assert text.count(PREVIOUS) == 1
        assert text.index(GATE) > text.index(PREVIOUS)


def test_rfc0037_threat_review_maps_exactly_48_invariants() -> None:
    path = ROOT / "docs/security/RFC-0037-durable-recovery-reliability-threat-model-review.md"
    text = path.read_text(encoding="utf-8")
    invariants = {
        int(value)
        for value in re.findall(
            r"^- Invariant ([0-9]+):",
            text,
            flags=re.MULTILINE,
        )
    }
    assert invariants == set(range(1, 49))
    assert "Recovery is continuation under fresh evidence, never replay by assumption." in text
    assert "A restart cannot increase authority, budget, lifetime, or certainty." in text


def test_rfc0037_migration_guidance_is_explicit_about_schema_and_rollback() -> None:
    path = ROOT / "docs/migrations/v0.36.0-to-v0.37.0-durable-recovery-reliability.md"
    text = path.read_text(encoding="utf-8")
    for marker in (
        "## Compatibility default",
        "## Durable SQLite migration",
        "schema version 5",
        "freshness witness",
        "## Recovery behavior",
        "## Rollback guidance",
        "Do not attempt an in-place schema downgrade",
        "## Release-gate adoption",
    ):
        assert marker in text


def test_reliability_gate_manifest_covers_reviewed_high_risk_surfaces() -> None:
    text = (ROOT / "scripts/check_reliability_release.py").read_text(encoding="utf-8")
    for marker in (
        "test_agent_durable_mutation.py",
        "test_agent_durable_integrity_adversarial.py",
        "test_agent_durable_lease_fencing_adversarial.py",
        "test_agent_durable_recovery_concurrency.py",
        "test_agent_durable_attempts.py",
        "test_agent_durable_reconciliation.py",
        "test_integrated_agent_durable_live_revalidation.py",
        "test_agent_durable_reliability_matrix.py",
        "production_fault_injector_absence",
    ):
        assert marker in text
