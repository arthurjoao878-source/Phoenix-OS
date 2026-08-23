from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0033-effective-authority-and-capability-non-amplification.md"


def test_rfc0033_is_accepted_and_names_release_gate() -> None:
    text = _RFC.read_text(encoding="utf-8")
    assert "- Status: Accepted" in text
    assert "- Target release: Phoenix OS v0.33.0" in text
    assert "python scripts/check_authority_release.py" in text
    assert "- [ ]" not in text


def test_rfc0033_keeps_canonical_non_amplification_principle() -> None:
    text = " ".join(_RFC.read_text(encoding="utf-8").replace("\n> ", "\n").split())
    assert (
        "Every protected operation remains dominated by its canonical authority boundary, "
        "regardless of how that operation is reached."
    ) in text
    assert "effective authority as a point-in-time result of current trusted state" in text


def test_rfc0033_names_all_dedicated_authority_tests() -> None:
    text = _RFC.read_text(encoding="utf-8")
    for relative in (
        "tests/test_authority_contracts.py",
        "tests/test_authority_subject_binding.py",
        "tests/test_authority_freshness.py",
        "tests/test_authority_composition.py",
        "tests/test_authority_adversarial.py",
        "tests/test_authority_explain.py",
        "tests/test_authority_redaction.py",
        "tests/test_authority_security_review.py",
        "tests/test_rfc_0033.py",
        "tests/test_authority_release_gate.py",
    ):
        assert relative in text
