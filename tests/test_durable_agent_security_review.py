from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_REVIEW = _ROOT / "docs" / "security" / "RFC-0028-durable-agent-threat-model-review.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0028-durable-agent-runs-and-controlled-resumption.md"
_README = _ROOT / "README.md"


def _review() -> str:
    return _REVIEW.read_text(encoding="utf-8")


def _normalized() -> str:
    return " ".join(_review().split())


def test_durable_security_review_is_linked_and_accepted() -> None:
    assert _REVIEW.is_file()
    review = _review()
    assert "**Reviewed:** 2026-08-10" in review
    assert "**Release:** Phoenix OS v0.28.0" in review
    assert "**Result:** Accepted for the v0.28.0 durable-agent release gate" in review
    assert "RFC-0028-durable-agent-threat-model-review.md" in _RFC.read_text(encoding="utf-8")
    assert "docs/security/RFC-0028-durable-agent-threat-model-review.md" in (
        _README.read_text(encoding="utf-8")
    )


def test_durable_security_review_covers_all_forty_five_invariants() -> None:
    review = _normalized()
    assert "all forty-five security invariants" in review
    for heading in (
        "Invariants 1\u20136",
        "Invariants 7\u201314",
        "Invariants 15\u201321",
        "Invariants 22\u201328",
        "Invariants 29\u201334",
        "Invariants 35\u201337",
        "Invariants 38\u201340",
        "Invariants 41\u201344",
        "Invariant 45",
    ):
        assert heading in review


def test_durable_security_review_preserves_checkpoint_and_authority_boundaries() -> None:
    review = _normalized()
    for phrase in (
        "Checkpoint is data only",
        "fresh exact resume, model, and tool authorization",
        "Current configuration, registry, schemas, limits, policy",
        "approval evidence remains exact and current",
        "store-side mutation requires the current lease/generation",
        "Stale workers cannot mutate",
    ):
        assert phrase in review


def test_durable_security_review_preserves_indeterminate_no_retry_semantics() -> None:
    review = _normalized()
    for phrase in (
        "active external attempt at process loss is indeterminate",
        "Indeterminate work is never retried automatically",
        "does not claim exactly-once side effects",
        "reconciliation cannot rewrite the original invocation identity",
        "Idempotency keys reduce duplicate risk",
    ):
        assert phrase in review


def test_durable_security_review_preserves_protected_content_and_retention() -> None:
    review = _normalized()
    for phrase in (
        "metadata-only by default",
        "Protected continuation content is explicit opt-in",
        "Encryption does not replace authorization",
        "never falls back to plaintext",
        "actively leased runs are not cleanup candidates",
        "terminal tombstones prevent stale state",
    ):
        assert phrase in review


def test_durable_security_review_preserves_safe_operations_and_compatibility() -> None:
    review = _normalized()
    for phrase in (
        "Machine administration default-off",
        "public failures omit protected or execution content",
        "recovered tool results remain untrusted",
        "durable recovery cannot recursively",
        "retains v0.27.0 behavior",
        "does not by itself accept RFC-0028 or authorize publication",
    ):
        assert phrase in review


def test_durable_security_review_references_existing_regression_evidence() -> None:
    names = set(re.findall(r"`(test_[a-z0-9_]+\.py)`", _review()))
    assert len(names) >= 20
    missing = sorted(name for name in names if not (_ROOT / "tests" / name).is_file())
    assert not missing, f"review references missing test files: {missing}"


def test_durable_security_review_records_residual_risks() -> None:
    review = _normalized()
    for phrase in (
        "installed storage, model, tool, secret, or reconciliation adapter",
        "does not replace trusted storage access control",
        "exactly-once execution is not promised",
        "retained protected payloads permanently unrecoverable",
        "operational traffic patterns",
        "Restoring an old database or backup",
    ):
        assert phrase in review


def test_rfc_0028_marks_security_review_complete() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- [x] Threat-model and security-invariant review" in rfc


def test_durable_security_review_contains_no_unsafe_advice() -> None:
    review = _normalized()
    forbidden = (
        'api_key = "',
        'password = "',
        'secret = "',
        "grant `*`",
        "retry indeterminate attempts automatically",
        "checkpoint grants authority",
        "fall back to plaintext",
        "disable fencing",
    )
    for phrase in forbidden:
        assert phrase not in review
