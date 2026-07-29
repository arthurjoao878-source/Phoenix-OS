from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_REVIEW = _ROOT / "docs" / "security" / "RFC-0027-agent-threat-model-review.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0027-secure-agent-loop-and-tool-calling.md"
_README = _ROOT / "README.md"


def _normalized() -> str:
    return " ".join(_REVIEW.read_text(encoding="utf-8").split())


def test_agent_security_review_is_linked_and_accepted() -> None:
    assert _REVIEW.is_file()
    review = _REVIEW.read_text(encoding="utf-8")
    assert "**Reviewed:** 2026-07-29" in review
    assert "**Result:** Accepted for the v0.27.0 release gate" in review
    assert "RFC-0027-agent-threat-model-review.md" in _RFC.read_text(encoding="utf-8")
    assert "docs/security/RFC-0027-agent-threat-model-review.md" in _README.read_text(
        encoding="utf-8"
    )


def test_agent_security_review_maps_required_threats_to_tests() -> None:
    review = _normalized()
    for phrase in (
        "Prompt injection selects privileged execution",
        "Fabricated tool or resource",
        "Schema confusion, duplicate keys, argument smuggling",
        "Approval replay or mutation",
        "Authority inherited from the outer run",
        "Infinite loops and resource exhaustion",
        "Duplicate side effects",
        "Tool-result prompt injection",
        "Cancellation and shutdown races",
        "Audit or logging disclosure",
        "Ambient authority in tools",
        "Source tree differs from shipped package",
    ):
        assert phrase in review


def test_agent_security_review_covers_all_invariant_groups() -> None:
    review = _normalized()
    for phrase in (
        "Invariants 1\N{EN DASH}6: opt-in and server-owned tools",
        "Invariants 7\N{EN DASH}11: independent authorization and trusted resources",
        "Invariants 12\N{EN DASH}15: strict canonical data",
        "Invariants 16\N{EN DASH}18: exact approval",
        "Invariants 19\N{EN DASH}22: adapter authority and serial execution",
        "Invariants 23\N{EN DASH}30: finite limits, no retry, cancellation, terminal state",
        "Invariants 31\N{EN DASH}33: fail-closed transitions, recursion, persistence",
        "Invariants 34\N{EN DASH}35: safe outputs and public failures",
        "Invariant 36: v0.26.0 compatibility",
    ):
        assert phrase in review
    assert review.count("Result: satisfied.") == 9


def test_agent_security_review_records_residual_risks_and_non_goals() -> None:
    review = _normalized()
    for phrase in (
        "installed tool adapter can abuse authority",
        "cannot promise exactly-once execution",
        "Prompt and tool-result injection can still influence later model output",
        "Autonomous scheduling, remote machine administration, arbitrary shell",
        "requires a separate reviewed contract",
    ):
        assert phrase in review


def test_agent_security_review_requires_named_isolated_release_gate() -> None:
    review = _normalized()
    for phrase in (
        "python scripts/check_agent_release.py",
        "build and inspect wheel and sdist artifacts",
        "isolated offline environments",
        "without source-tree imports",
    ):
        assert phrase in review
