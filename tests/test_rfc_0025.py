from __future__ import annotations

import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_RFC = (
    _ROOT / "docs" / "rfcs" / "RFC-0025-secure-inbound-event-gateway-and-external-event-sources.md"
)
_README = _ROOT / "README.md"
_PYPROJECT = _ROOT / "pyproject.toml"


def test_rfc_0025_metadata_is_accepted_for_v0250() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert rfc.startswith("# RFC-0025: Secure Inbound Event Gateway and External Event Sources")
    assert "- Status: Accepted" in rfc
    assert "- Target release: Phoenix OS v0.25.0" in rfc


def test_readme_lists_rfc_0025_as_accepted() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "Version `0.25.0` implements twenty-five accepted specifications:" in readme
    assert "## Draft specifications" not in readme
    assert "**RFC-0025 — Secure Inbound Event Gateway and External Event Sources:**" in readme


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
    assert project["project"]["version"] == "0.25.0"
    assert "Inbound sources are optional and begin empty." in rfc
    assert "Existing webhook subscriptions are not converted" in rfc
    assert "receive no inbound scopes or source resources automatically" in rfc
    assert "remained `0.24.0` during implementation slices" in rfc
    assert "`0.25.0` in the final release slice" in rfc


def test_rfc_0025_slice_1_is_implemented() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    plan = rfc.split("## Slice plan", maxsplit=1)[1].split("## Acceptance", maxsplit=1)[0]
    slice_1 = plan.split("### Slice 2", maxsplit=1)[0]

    assert plan.count("- [x]") == 36
    assert plan.count("- [ ]") == 0
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


def test_rfc_0025_slice_2_authentication_foundation_is_implemented() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    plan = rfc.split("## Slice plan", maxsplit=1)[1].split("## Acceptance", maxsplit=1)[0]
    slice_2 = plan.split("### Slice 2", maxsplit=1)[1].split("### Slice 3", maxsplit=1)[0]

    assert slice_2.count("- [x]") == 7
    assert slice_2.count("- [ ]") == 0
    assert "- [x] Versioned HMAC-SHA-256 verification" in slice_2
    assert "- [x] Exact Secrets Vault key-version resolution" in slice_2
    assert "- [x] RFC-0023 service-account authentication mode" in slice_2
    assert "- [x] Timestamp, nonce, and request-identifier validation" in slice_2
    assert "- [x] Durable replay protection across restart" in slice_2
    assert "- [x] Stable source-event idempotency and conflict rejection" in slice_2
    assert "- [x] Generic authentication and enumeration-resistance tests" in slice_2


def test_rfc_0025_slice_3_transport_and_schema_foundation_is_implemented() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    plan = rfc.split("## Slice plan", maxsplit=1)[1].split("## Acceptance", maxsplit=1)[0]
    slice_3 = plan.split("### Slice 3", maxsplit=1)[1].split("### Slice 4", maxsplit=1)[0]

    assert slice_3.count("- [x]") == 8
    assert slice_3.count("- [ ]") == 0
    assert "- [x] Fixed opt-in inbound route" in slice_3
    assert "- [x] Exact media-type and security-header validation" in slice_3
    assert "- [x] Bounded body and structural JSON parsing" in slice_3
    assert "- [x] Explicit schema registry and normalizers" in slice_3
    assert "- [x] Policy-protected durable acceptance" in slice_3
    assert "- [x] Per-source and global admission limits" in slice_3
    assert "- [x] Safe receipts and HTTP error mapping" in slice_3
    assert "- [x] TLS, proxy, CIDR, smuggling, and malformed-input tests" in slice_3


def test_rfc_0025_slice_4_publisher_foundation_is_implemented() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    plan = rfc.split("## Slice plan", maxsplit=1)[1].split("## Acceptance", maxsplit=1)[0]
    slice_4 = plan.split("### Slice 4", maxsplit=1)[1].split("### Slice 5", maxsplit=1)[0]

    assert slice_4.count("- [x]") == 7
    assert slice_4.count("- [ ]") == 0
    assert "- [x] Runtime-owned asynchronous Event Bus publisher" in slice_4
    assert "- [x] Deterministic bounded retry and dead-letter handling" in slice_4
    assert "- [x] Interrupted-publication recovery" in slice_4
    assert "- [x] Explicit eligible redrive" in slice_4
    assert "- [x] Safe audit facts, metrics, and health snapshots" in slice_4
    assert "- [x] Retention and recovery workers" in slice_4
    assert "- [x] At-least-once and stable-identity regression tests" in slice_4


def test_rfc_0025_slice_5_administration_foundation_is_implemented() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    plan = rfc.split("## Slice plan", maxsplit=1)[1].split("## Acceptance", maxsplit=1)[0]
    slice_5 = plan.split("### Slice 5", maxsplit=1)[1]

    assert slice_5.count("- [x]") == 8
    assert slice_5.count("- [ ]") == 0
    assert "- [x] Maintainer-only source and event administration" in slice_5
    assert "- [x] Dashboard source, receipt, history, and dead-letter administration" in slice_5
    assert "- [x] Optional scoped service-account administration" in slice_5
    assert "- [x] RuntimeAssembler integration and lifecycle ownership" in slice_5
    assert "- [x] Migration guidance" in slice_5
    assert "- [x] Architecture Decision Records" in slice_5
    assert "- [x] Regression, authentication, replay, admission, and packaging gate" in slice_5
    assert "- [x] Release notes and version 0.25.0" in slice_5
