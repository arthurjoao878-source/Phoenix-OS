from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_REVIEW = _ROOT / "docs" / "security" / "RFC-0033-effective-authority-threat-model-review.md"


def test_authority_security_review_covers_required_review_structure() -> None:
    text = _REVIEW.read_text(encoding="utf-8")
    for heading in (
        "## Review method",
        "## Trust boundaries",
        "## Threat review",
        "## Security-invariant review",
        "## Residual risks",
        "## Release conclusion",
    ):
        assert heading in text


def test_authority_security_review_covers_rfc0033_adversarial_classes() -> None:
    text = " ".join(_REVIEW.read_text(encoding="utf-8").lower().split())
    for phrase in (
        "intersection",
        "subject substitution",
        "session",
        "agent",
        "run",
        "final untrusted wait",
        "approval",
        "resource rebirth",
        "confused deputy",
        "cross-agent",
        "inspection",
        "redacted",
        "non-authoritative",
        "attribute-derived session",
        "closed-world",
        "unknown operation",
        "point-in-time",
    ):
        assert phrase in text
