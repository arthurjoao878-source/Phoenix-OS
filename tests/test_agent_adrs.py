from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_ADRS = _ROOT / "docs" / "adrs"
_INDEX = _ADRS / "README.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0027-secure-agent-loop-and-tool-calling.md"
_README = _ROOT / "README.md"

_ADR_FILES = (
    "ADR-0016-server-owned-tool-registry-and-strict-agent-schemas.md",
    "ADR-0017-independent-agent-model-tool-authorization-and-exact-approvals.md",
    "ADR-0018-bounded-serial-agent-loop-and-no-transparent-retry.md",
    "ADR-0019-untrusted-tool-results-and-content-free-agent-observability.md",
    "ADR-0020-opt-in-agent-runtime-and-bounded-lifecycle.md",
)


def _read(name: str) -> str:
    return (_ADRS / name).read_text(encoding="utf-8")


def _normalized(name: str) -> str:
    return " ".join(_read(name).split())


def test_agent_adr_index_links_every_record() -> None:
    index = _INDEX.read_text(encoding="utf-8")
    for name in _ADR_FILES:
        assert name in index


def test_agent_adrs_use_complete_accepted_structure() -> None:
    for name in _ADR_FILES:
        document = _read(name)
        assert "- **Status:** Accepted" in document
        assert "- **Date:** 2026-07-29" in document
        assert "RFC-0027" in document
        assert "## Context" in document
        assert "## Decision" in document
        assert "## Consequences" in document
        assert "## Alternatives considered" in document
        assert "## Supersession criteria" in document


def test_tool_registry_adr_records_server_owned_strict_boundary() -> None:
    document = _read(_ADR_FILES[0])
    normalized = _normalized(_ADR_FILES[0])
    assert "`ToolRegistry`" in document
    assert "only tool allowlisting boundary" in normalized
    assert "Models may select only a registered identifier" in normalized
    assert "Duplicate JSON keys" in document
    assert "deterministic fake model adapter" in normalized


def test_authorization_adr_records_independent_decisions_and_exact_approval() -> None:
    document = _read(_ADR_FILES[1])
    normalized = _normalized(_ADR_FILES[1])
    for phrase in ("`agent.run`", "`model.infer`", "`tool.invoke`"):
        assert phrase in document
    assert "trusted server-side code" in normalized
    assert "single-use and replay-resistant" in normalized
    assert "A model cannot create, modify, consume, or extend approval evidence" in normalized


def test_execution_adr_records_finite_serial_no_retry_semantics() -> None:
    normalized = _normalized(_ADR_FILES[2])
    for phrase in (
        "at most one tool call per model turn",
        "The most restrictive applicable limit wins",
        "There is no transparent retry",
        "safe indeterminate failure",
        "Cancellation rejects new work",
    ):
        assert phrase in normalized


def test_observability_adr_records_untrusted_results_and_content_free_output() -> None:
    normalized = _normalized(_ADR_FILES[3])
    for phrase in (
        "Tool output remains untrusted data",
        "content-free by default",
        "fixed event types and empty payloads",
        "do not enumerate the registered tool inventory",
    ):
        assert phrase in normalized


def test_lifecycle_adr_records_opt_in_rollback_and_shutdown_ordering() -> None:
    document = _read(_ADR_FILES[4])
    normalized = _normalized(_ADR_FILES[4])
    assert "disabled by default" in document
    assert "`RuntimeAssembler`" in document
    assert "No background planner, scheduler, listener, shell" in normalized
    assert "reverse composition order" in normalized
    assert "preserves RFC-0026 inference shutdown ordering" in normalized
    assert "Machine administration is not introduced" in normalized


def test_agent_adrs_do_not_contain_unsafe_advice() -> None:
    joined = "\n".join(_read(name) for name in _ADR_FILES)
    forbidden = (
        'api_key = "',
        'password = "',
        'secret = "',
        "grant `*`",
        "execute model output directly",
        "retry tool calls automatically",
        "register a generic shell",
    )
    for phrase in forbidden:
        assert phrase not in joined


def test_readme_and_rfc_link_the_agent_adr_collection() -> None:
    readme = _README.read_text(encoding="utf-8")
    rfc = _RFC.read_text(encoding="utf-8")
    assert "docs/adrs/README.md" in readme
    assert "RFC-0027 agent" in readme
    assert "- [x] Architecture Decision Records" in rfc
    for name in _ADR_FILES:
        assert name in rfc
