from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0029-secure-multi-agent-coordination-and-delegation.md"


def _text() -> str:
    return " ".join(_RFC.read_text(encoding="utf-8").split())


def test_rfc_0029_exists_as_v0290_draft() -> None:
    text = _text()
    assert "# RFC-0029: Secure Multi-Agent Coordination and Delegation" in text
    assert "- Status: Draft" in text
    assert "- Target release: Phoenix OS v0.29.0" in text


def test_delegation_creates_work_never_authority() -> None:
    text = _text()
    assert "Delegation creates work, never authority." in text
    assert "A parent transfers no policy authority to a child." in text
    assert "Parent permissions are never copied into the child security context." in text


def test_exact_authorization_is_separate() -> None:
    text = _text()
    assert "`agent.delegate`" in text
    assert "agent-delegation:<namespace>/parent:<parent-agent-id>/child:<child-agent-id>" in text
    assert "Every delegation requires a fresh exact `agent.delegate` authorization." in text
    assert "Delegation authorization is separate from `agent.run`, `model.infer`" in text


def test_recursion_fanout_concurrency_and_budget_are_bounded() -> None:
    text = _text()
    assert "Delegation depth has a finite configured maximum." in text
    assert "Per-parent fan-out has a finite configured maximum." in text
    assert "Concurrent child execution has a finite configured maximum." in text
    assert "Delegation cannot increase the root run's total configured budget." in text
    assert "One `DelegationId` is permanently bound to at most one child-run identity" in text
    assert "Completing a child releases concurrency capacity but does not restore" in text
    assert "One Runtime-owned cancellation token covers the entire queued-to-running child" in text
    assert "`create_agent_coordination_runtime_stack`" in text
    assert "Failed, cancelled, and timed-out children expose only a bounded safe" in text


def test_child_results_remain_untrusted() -> None:
    text = _text()
    assert (
        "Child output is untrusted data and never becomes policy or executable authority." in text
    )
    assert "content-free metadata only" in text


def test_durable_recovery_cannot_duplicate_child() -> None:
    text = _text()
    assert "One `DelegationId` cannot create two distinct child runs." in text
    assert "Durable recovery never silently duplicates an already-created child." in text
    assert "does not weaken RFC-0028 fencing" in text


def test_v0280_behavior_is_preserved_by_omission() -> None:
    text = _text()
    assert "Existing Phoenix OS v0.28.0 behavior remains unchanged" in text
    assert "RFC-0027/RFC-0028 behavior remains unchanged" in text


def test_slice_plan_starts_pending() -> None:
    text = _text()
    assert "### Slice 0 - RFC foundation and executable specification" in text
    assert "### Slice 5 - Security review, migration, and release hardening" in text
    assert "- [x] Draft RFC-0029 with explicit security invariants" in text
    assert "- [x] Add RFC structure and regression tests" in text
    assert "- [x] Establish exact action/resource naming" in text
    assert "- [x] Confirm compatibility-by-omission contract" in text
    assert "- [x] Immutable delegation contracts" in text
    assert "- [x] Bounded identifiers, statuses, lineage, limits, and budgets" in text
    assert "- [x] Server-owned child-agent registry" in text
    assert "- [x] Exact `agent.delegate` authorization boundary" in text
    assert "- [x] Deterministic contract and authorization tests" in text
    assert "- [x] Delegation coordinator" in text
    assert "- [x] Child admission and lifecycle state machine" in text
    assert "- [x] Depth, fan-out, concurrency, queue, deadline, and budget enforcement" in text
    assert "- [x] Cycle prevention and duplicate-identity rejection" in text
    assert "- [x] Deterministic race and limit tests" in text
    assert "- [x] Bounded child input/result validation" in text
    assert "- [x] Deterministic aggregation boundary" in text
    assert "- [x] Parent cancellation propagation" in text
    assert "- [x] Controlled shutdown and finite draining" in text
    assert "- [x] RuntimeAssembler opt-in composition" in text
    assert "- [x] Content-free observer and administration" in text
    assert "- [ ] Durable parent/child linkage" in text
    assert "- [ ] Tag, artifacts, and checksums" in text
