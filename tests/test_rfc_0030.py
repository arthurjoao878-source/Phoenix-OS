from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0030-secure-agent-memory-and-context-retrieval.md"


def _text() -> str:
    return " ".join(_RFC.read_text(encoding="utf-8").split())


def test_rfc_0030_exists_as_v0300_draft() -> None:
    text = _text()
    assert "# RFC-0030: Secure Agent Memory and Context Retrieval" in text
    assert "- Status: Draft" in text
    assert "- Target release: Phoenix OS v0.30.0" in text


def test_memory_informs_work_never_authority() -> None:
    text = _text()
    assert "Memory informs work, never authority." in text
    assert "Stored memory never carries or reconstructs policy authority." in text
    assert "Memory content is untrusted data." in text
    assert (
        "Retrieved memory never becomes system policy, an authorization decision, "
        "a tool directive, or executable authority." in text
    )


def test_exact_memory_authorization_surface_is_separate() -> None:
    text = _text()
    for action in (
        "memory.search",
        "memory.read",
        "memory.write",
        "memory.delete",
        "memory.admin",
    ):
        assert f"`{action}` authorization" in text or action in text

    assert "agent-memory:<namespace>/scope:<scope-kind>:<scope-id>" in text
    assert "agent-memory:<namespace>/scope:<scope-kind>:<scope-id>/record:<memory-id>" in text
    assert (
        "Memory authorization is separate from `agent.run`, `model.infer`, "
        "`tool.invoke`, `agent.delegate`, `agent.resume`, and `agent.reconcile`." in text
    )


def test_scope_isolation_and_delegation_do_not_implicitly_share_memory() -> None:
    text = _text()
    assert "the initial set is run, agent, and principal" in text
    assert "Memory is never implicitly shared across agents, principals, or runs." in text
    assert "Parent and child agents do not share memory by default." in text
    assert "Global shared memory is not supported in the initial version." in text
    assert "Model content cannot create, widen, replace, or mutate a memory scope." in text


def test_memory_writes_are_explicit_and_sensitive_implicit_capture_is_forbidden() -> None:
    text = _text()
    assert (
        "Phoenix does not automatically capture every prompt, response, tool result, "
        "or conversation as memory." in text
    )
    assert "Every memory write is an explicit server-admitted operation." in text
    assert "Chain-of-thought and hidden reasoning are never persisted" in text
    assert "Secrets and secret wrappers are rejected by default" in text
    assert "Every record has immutable bounded provenance." in text


def test_retrieval_and_context_are_strictly_bounded_and_untrusted() -> None:
    text = _text()
    assert "Search queries have strict byte and structural bounds." in text
    assert "Retrieval result count and total returned content bytes are strictly bounded." in text
    assert "Context assembly has strict item, byte, and ordering bounds." in text
    assert (
        "Context blocks preserve provenance and are explicitly labeled as untrusted retrieved data."
        in text
    )
    assert "Memory cannot expand the run's configured model/input/token authority" in text


def test_memory_poisoning_cannot_change_authority() -> None:
    text = _text()
    assert (
        "Stored prompt injection cannot alter current authorization, policy, scope, "
        "model, tool, delegation, or approval decisions." in text
    )
    assert "Memory content can contain malicious instructions." in text
    assert "stored content is never itself an authority channel." in text


def test_retrieval_indexes_are_derived_not_authoritative() -> None:
    text = _text()
    assert "The source store is authoritative" in text
    assert (
        "Every retrieval hit is revalidated against the authoritative source record "
        "before disclosure." in text
    )
    assert "Semantic/vector retrieval is optional and provider-neutral" in text
    assert "provider SDK objects never appear in public contracts." in text
    assert (
        "rejects stale, deleted, expired, mismatched-scope, wrong-version, or wrong-digest hits."
        in text
    )


def test_retention_deletion_and_recovery_fail_closed() -> None:
    text = _text()
    assert "Deleted memory cannot silently reappear" in text
    assert (
        "Every namespace/scope has an explicit retention policy with finite configured bounds."
        in text
    )
    assert (
        "Expired or tombstoned records are absent from reads, retrieval, context "
        "assembly, and recovery." in text
    )
    assert (
        "Unknown schema versions, corrupt records, invalid provenance, and "
        "inconsistent index references fail closed." in text
    )


def test_v0290_behavior_is_preserved_by_omission() -> None:
    text = _text()
    assert "Existing Phoenix OS v0.29.0 behavior remains unchanged" in text
    assert (
        "Existing Phoenix OS v0.29.0 agent, durable-agent, and multi-agent behavior "
        "remains unchanged." in text
    )


def test_slice_plan_starts_with_only_slice_zero_complete() -> None:
    text = _text()
    assert "### Slice 0 - RFC foundation and executable specification" in text
    assert "### Slice 5 - Security review, migration, and release hardening" in text

    for item in (
        "Draft RFC-0030 with explicit security invariants",
        "Define exact memory action/resource naming",
        "Define scope-isolation and untrusted-context principles",
        "Establish compatibility-by-omission contract",
        "Add RFC structure and regression tests",
    ):
        assert f"- [x] {item}" in text

    assert (
        "- [ ] Immutable memory identifiers, scopes, versions, provenance, retention, and limits"
        in text
    )
    assert "- [ ] Reference authoritative memory store" in text
    assert "- [ ] Bounded retrieval requests and results" in text
    assert "- [ ] Provider-neutral optional semantic/vector retrieval boundary" in text
    assert "- [ ] Threat-model/security-invariant review" in text
    assert "- [ ] Tag, artifacts, and checksums" in text
