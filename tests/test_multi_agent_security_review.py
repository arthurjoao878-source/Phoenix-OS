from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_REVIEW = _ROOT / "docs" / "security" / "RFC-0029-multi-agent-threat-model-review.md"


def test_multi_agent_security_review_covers_all_invariants() -> None:
    text = _REVIEW.read_text(encoding="utf-8")
    assert "all forty-five security invariants" in text
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
        "Invariants 1-8",
        "Invariants 9-15",
        "Invariants 16-24",
        "Invariants 25-31",
        "Invariants 32-35",
        "Invariants 36-39",
        "Invariants 40-44",
        "Invariant 45",
    ):
        assert marker in text


def test_multi_agent_security_review_records_duplicate_prevention_and_no_authority_transfer() -> (
    None
):
    text = _REVIEW.read_text(encoding="utf-8")
    for phrase in (
        "Fresh exact `agent.delegate`",
        "no copied security authority",
        "Stable `DelegationId` to one child-run binding",
        "`RUNNING` becomes `INDETERMINATE`",
        "no automatic replay",
        "Durable lifetime accounting includes terminal records",
        "RFC-0029 is not a hostile-code sandbox",
    ):
        assert phrase in text
