from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_ADRS = _ROOT / "docs" / "adrs"
_INDEX = _ADRS / "README.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0028-durable-agent-runs-and-controlled-resumption.md"
_README = _ROOT / "README.md"

_ADR_FILES = (
    "ADR-0021-untrusted-canonical-chained-durable-checkpoints.md",
    "ADR-0022-fenced-leases-and-conditional-durable-mutation.md",
    "ADR-0023-controlled-recovery-and-explicit-indeterminate-reconciliation.md",
    "ADR-0024-opt-in-protected-payloads-and-content-free-durable-operations.md",
    "ADR-0025-opt-in-runtime-owned-durable-lifecycle-retention-and-administration.md",
)


def _read(name: str) -> str:
    return (_ADRS / name).read_text(encoding="utf-8")


def _normalized(name: str) -> str:
    return " ".join(_read(name).split())


def test_durable_agent_adr_index_links_every_record() -> None:
    index = _INDEX.read_text(encoding="utf-8")
    for name in _ADR_FILES:
        assert name in index
    assert "ADR-0021 through ADR-0025" in index
    assert "RFC-0028" in index


def test_durable_agent_adrs_use_complete_accepted_structure() -> None:
    for name in _ADR_FILES:
        document = _read(name)
        assert "- **Status:** Accepted" in document
        assert "- **Date:** 2026-08-10" in document
        assert "- **Related:** RFC-0028" in document
        assert "## Context" in document
        assert "## Decision" in document
        assert "## Consequences" in document
        assert "## Alternatives considered" in document
        assert "## Supersession criteria" in document


def test_checkpoint_adr_records_data_not_authority_and_chain_validation() -> None:
    normalized = _normalized(_ADR_FILES[0])
    for phrase in (
        "treats every durable checkpoint as untrusted data",
        "A checkpoint grants no policy decision, approval, credential, lease",
        "strictly increasing sequence",
        "expected previous checkpoint digest",
        "cross-run substitution",
        "Current configuration, registry, schemas, limits, policy",
    ):
        assert phrase in normalized


def test_fencing_adr_records_store_enforced_stale_worker_rejection() -> None:
    normalized = _normalized(_ADR_FILES[1])
    for phrase in (
        "strictly increasing fencing generation",
        "expected run version, lease identifier, and current fencing generation",
        "Store-side conditional mutation is authoritative",
        "re-reads the current checkpoint",
        "loses renewal stops admitting new model and tool work",
        "Fencing generations are not client-selected administration authority",
    ):
        assert phrase in normalized


def test_recovery_adr_records_fresh_authority_and_no_ambiguous_retry() -> None:
    normalized = _normalized(_ADR_FILES[2])
    for phrase in (
        "fresh exact `agent.resume` authorization",
        "fresh RFC-0026 `model.infer` decision",
        "fresh exact `tool.invoke` decision",
        "becomes indeterminate",
        "never retried automatically",
        "explicit separate action over the exact durable run and attempt",
        "does not claim exactly-once external side effects",
    ):
        assert phrase in normalized


def test_protected_payload_adr_records_metadata_default_and_safe_output() -> None:
    normalized = _normalized(_ADR_FILES[3])
    for phrase in (
        "`METADATA_ONLY` as the default durable payload profile",
        "`PROTECTED_CONTENT` is explicit opt-in",
        "authenticated encryption",
        "versioned configured protection keys",
        "Decryption occurs only after authorization, fenced lease acquisition",
        "Encryption never replaces authorization",
        "remain content-free",
        "shorter than reviewed content-free metadata retention",
    ):
        assert phrase in normalized


def test_lifecycle_adr_records_opt_in_retention_and_administration_boundaries() -> None:
    normalized = _normalized(_ADR_FILES[4])
    for phrase in (
        "optional, disabled by default",
        "`RuntimeAssembler` creates no durable run",
        "Partial startup rolls back deterministically",
        "cannot create new goals",
        "delegated to the Runtime-owned bounded retention worker",
        "Wildcard permissions do not satisfy exact destructive authority",
        "Machine administration is disabled by default",
        "no machine cleanup endpoint",
    ):
        assert phrase in normalized


def test_durable_agent_adrs_do_not_contain_unsafe_advice() -> None:
    joined = "\n".join(_read(name) for name in _ADR_FILES)
    forbidden = (
        'api_key = "',
        'password = "',
        'secret = "',
        "grant `*`",
        "retry indeterminate attempts automatically",
        "checkpoint grants authority",
        "client-selected fencing generation",
        "fall back to plaintext",
    )
    for phrase in forbidden:
        assert phrase not in joined


def test_readme_and_rfc_link_durable_agent_adr_collection() -> None:
    readme = _README.read_text(encoding="utf-8")
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- [x] Architecture Decision Records" in rfc
    assert "RFC-0028 durable-agent records" in readme
    for name in _ADR_FILES:
        assert name in rfc
        assert name in _INDEX.read_text(encoding="utf-8")
