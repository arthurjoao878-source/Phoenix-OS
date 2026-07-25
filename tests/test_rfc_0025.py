from __future__ import annotations

import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_RFC = (
    _ROOT / "docs" / "rfcs" / "RFC-0025-secure-inbound-event-gateway-and-external-event-sources.md"
)
_README = _ROOT / "README.md"
_PYPROJECT = _ROOT / "pyproject.toml"


def test_rfc_0025_metadata_is_draft_for_v0250() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert rfc.startswith("# RFC-0025: Secure Inbound Event Gateway and External Event Sources")
    assert "- Status: Draft" in rfc
    assert "- Target release: Phoenix OS v0.25.0" in rfc


def test_readme_lists_rfc_0025_as_draft_not_accepted() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "Version `0.24.0` implements twenty-four accepted specifications:" in readme
    assert "## Draft specifications" in readme
    accepted, draft = readme.split("## Draft specifications", maxsplit=1)
    assert "RFC-0025" not in accepted
    assert "RFC-0025" in draft


def test_rfc_0025_has_required_design_sections() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    required = (
        "## Summary",
        "## Motivation",
        "## Goals",
        "## Non-goals",
        "## Threat model",
        "## Security invariants",
        "## Proposed contracts",
        "## Ingress HTTP protocol",
        "## Persistence and recovery",
        "## RuntimeAssembler integration",
        "## Compatibility and migration",
        "## Slice plan",
        "## Acceptance",
    )
    for heading in required:
        assert heading in rfc


def test_rfc_0025_defines_fail_closed_ingress() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    for phrase in (
        "disabled by default",
        "Raw request bodies are never published directly",
        "Callers cannot choose arbitrary internal Event Bus event names",
        "Browser cookies, CSRF proofs, operator sessions",
        "External source identity never implies operator",
    ):
        assert phrase in rfc


def test_rfc_0025_defines_authentication_and_replay_evidence() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    for phrase in (
        "X-Phoenix-Inbound-Request-Id",
        "X-Phoenix-Inbound-Event-Id",
        "X-Phoenix-Inbound-Timestamp",
        "X-Phoenix-Inbound-Nonce",
        "X-Phoenix-Inbound-Signature",
        "X-Phoenix-Inbound-Key-Version",
        "inbound_event.submit",
        "Replay reservations survive Runtime and process restarts",
    ):
        assert phrase in rfc


def test_rfc_0025_defines_durable_idempotent_acceptance() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    for phrase in (
        "accepted-event persistence are atomic",
        "success response is not returned until durable acceptance commits",
        "same normalized digest returns the same stable receipt",
        "different normalized digest returns a generic conflict",
        "Event publication is asynchronous and at-least-once",
    ):
        assert phrase in rfc


def test_rfc_0025_preserves_v0240_compatibility() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    project = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    assert project["project"]["version"] == "0.24.0"
    assert "Inbound sources are optional and begin empty." in rfc
    assert "Existing webhook subscriptions are not converted" in rfc
    assert "receive no inbound scopes or source resources automatically" in rfc
    assert "changes to\n`0.25.0` only in the final release slice" in rfc


def test_rfc_0025_slice_1_is_implemented() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    plan = rfc.split("## Slice plan", maxsplit=1)[1].split("## Acceptance", maxsplit=1)[0]
    slice_1 = plan.split("### Slice 2", maxsplit=1)[0]

    assert plan.count("- [x]") == 6
    assert plan.count("- [ ]") == 30
    assert slice_1.count("- [x]") == 6
    assert slice_1.count("- [ ]") == 0
    assert (
        "- [x] Immutable source, schema, accepted-event, attempt, receipt, "
        "and replay contracts" in slice_1
    )
    assert "- [x] Strict schema-versioned codecs" in slice_1
    assert "- [x] In-memory source, event, and replay repositories" in slice_1
    assert "- [x] State Store-backed source, event, and replay repositories" in slice_1
    assert "- [x] Atomic replay reservation and accepted-event persistence" in slice_1
    assert "- [x] Repository equivalence and corruption tests" in slice_1
