import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_REVIEW = _ROOT / "docs" / "security" / "RFC-0034-secure-network-egress-threat-model-review.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0034-secure-network-egress-and-controlled-http-operations.md"


def test_network_security_review_maps_all_rfc0034_invariants_exactly_once() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    review = _REVIEW.read_text(encoding="utf-8")
    invariant_section = rfc.split("## Security invariants", 1)[1].split("## Slice plan", 1)[0]
    rfc_numbers = [int(m.group(1)) for m in re.finditer(r"(?m)^(\d+)\. ", invariant_section)]
    review_numbers = [int(m.group(1)) for m in re.finditer(r"(?m)^- Invariant (\d+):", review)]
    assert rfc_numbers == list(range(1, 46))
    assert review_numbers == list(range(1, 46))
    assert len(review_numbers) == len(set(review_numbers))


def test_network_security_review_covers_dominant_boundaries_and_release_evidence() -> None:
    text = " ".join(_REVIEW.read_text(encoding="utf-8").split())
    for phrase in (
        "Remote data is data. Network effects require fresh, exact, server-owned authority.",
        "Every protected operation remains dominated by its canonical authority boundary",
        "Attacker-controlled waits and final effect boundary",
        "DNS rebinding",
        "ambient proxy",
        "credential",
        "confused-deputy",
        "indeterminate",
        "content-free",
        "python scripts/check_network_egress_release.py",
        "Python 3.12/3.13",
        "Annotated",
        "Residual risks",
    ):
        assert phrase.lower() in text.lower()
