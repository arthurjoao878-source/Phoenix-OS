from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_REVIEW = _ROOT / "docs" / "security" / "RFC-0030-agent-memory-threat-model-review.md"


def test_agent_memory_security_review_covers_all_invariants() -> None:
    text = _REVIEW.read_text(encoding="utf-8")
    assert "all fifty-four security invariants" in text
    for heading in (
        "## Review method",
        "## Trust boundaries",
        "## Threat review",
        "## Security-invariant review",
        "## Residual risks",
        "## Release conclusion",
    ):
        assert heading in text
    for marker in (
        "Invariants 1-7",
        "Invariants 8-15",
        "Invariants 16-23",
        "Invariants 24-31",
        "Invariants 32-39",
        "Invariants 40-45",
        "Invariants 46-49",
        "Invariants 50-53",
        "Invariant 54",
    ):
        assert marker in text


def test_agent_memory_security_review_records_core_authority_and_recovery_boundaries() -> None:
    text = " ".join(_REVIEW.read_text(encoding="utf-8").split())
    for phrase in (
        "Memory informs work, never authority.",
        "Fresh exact memory action/resource authorization",
        "No global shared scope exists",
        "does not automatically capture ordinary prompts",
        "Source-store re-read plus exact version/digest validation",
        "cannot disclose a record or resurrect it after restart",
        "failed startup self-cleans",
        "content-free operations",
        "RFC-0030 is not a hostile-code sandbox",
    ):
        assert phrase in text
