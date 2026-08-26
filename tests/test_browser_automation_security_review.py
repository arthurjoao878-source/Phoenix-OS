import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_REVIEW = _ROOT / "docs" / "security" / "RFC-0035-secure-browser-automation-threat-model-review.md"


def test_browser_security_review_maps_all_fifty_invariants_exactly_once() -> None:
    text = _REVIEW.read_text(encoding="utf-8")
    numbers = [int(value) for value in re.findall(r"^- Invariant (\d+):", text, flags=re.MULTILINE)]
    assert numbers == list(range(1, 51))


def test_browser_security_review_covers_final_boundary_and_adversarial_cases() -> None:
    text = _REVIEW.read_text(encoding="utf-8")
    for phrase in (
        "zero-effect",
        "After the final such wait",
        "No observer, audit, Event Bus, log, metric, health, or inspection await",
        "`INDETERMINATE`",
        "mixed safe/unsafe",
        "cross-principal/session/agent/run",
        "observer-induced waits",
        "retry after indeterminate effect",
    ):
        assert phrase in text


def test_browser_security_review_defines_content_free_runtime_and_package_gate() -> None:
    text = _REVIEW.read_text(encoding="utf-8")
    for phrase in (
        "`browser.health.read`",
        "Security quarantine is distinct",
        "content-free",
        "python scripts/check_browser_automation_release.py",
        "isolated offline",
        "S7 does not change package version",
        "all fifty invariants",
    ):
        assert phrase in text
    assert "TODO" not in text
