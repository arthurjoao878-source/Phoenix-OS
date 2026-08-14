from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_REVIEW = _ROOT / "docs" / "security" / "RFC-0031-agent-workspace-threat-model-review.md"


def test_agent_workspace_security_review_covers_all_invariants() -> None:
    text = _REVIEW.read_text(encoding="utf-8")
    assert "all seventy-one security invariants" in text
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
        "Invariants 1-9",
        "Invariants 10-23",
        "Invariants 24-32",
        "Invariants 33-45",
        "Invariants 46-57",
        "Invariants 58-64",
        "Invariants 65-71",
    ):
        assert marker in text


def test_agent_workspace_security_review_records_core_security_boundaries() -> None:
    text = " ".join(_REVIEW.read_text(encoding="utf-8").split())
    for phrase in (
        "Files carry data, never authority.",
        "Fresh independent `workspace.*` action/resource authorization",
        "Canonical relative logical paths separated from opaque backing keys",
        "Atomic authoritative admission and deterministic collision checks",
        "Tombstones, identity anti-reuse, retention checks",
        "Explicit independent transfer authorization",
        "Bounded explicit untrusted USER context",
        "content-free bounded projections",
        "RFC-0031 is not a hostile-code sandbox",
    ):
        assert phrase in text
