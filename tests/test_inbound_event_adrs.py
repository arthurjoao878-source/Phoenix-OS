from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_ADRS = _ROOT / "docs" / "adrs"
_INDEX = _ADRS / "README.md"
_RFC = (
    _ROOT / "docs" / "rfcs" / "RFC-0025-secure-inbound-event-gateway-and-external-event-sources.md"
)
_README = _ROOT / "README.md"

_ADR_FILES = (
    "ADR-0006-reviewed-inbound-schemas-and-normalization.md",
    "ADR-0007-per-source-authentication-replay-and-idempotency.md",
    "ADR-0008-shared-control-plane-listener-and-exact-inbound-routes.md",
    "ADR-0009-durable-acceptance-and-at-least-once-publication.md",
    "ADR-0010-opt-in-inbound-runtime-and-separated-administration.md",
)


def _read(name: str) -> str:
    return (_ADRS / name).read_text(encoding="utf-8")


def _normalized(name: str) -> str:
    return " ".join(_read(name).split())


def test_inbound_adr_index_links_every_record() -> None:
    index = _INDEX.read_text(encoding="utf-8")
    for name in _ADR_FILES:
        assert name in index


def test_inbound_adrs_use_complete_accepted_structure() -> None:
    for name in _ADR_FILES:
        document = _read(name)
        assert "- **Status:** Accepted" in document
        assert "- **Date:** 2026-07-25" in document
        assert "RFC-0025" in document
        assert "## Context" in document
        assert "## Decision" in document
        assert "## Consequences" in document
        assert "## Alternatives considered" in document
        assert "## Supersession criteria" in document


def test_schema_adr_records_reviewed_allowlisting_boundary() -> None:
    document = _read(_ADR_FILES[0])
    normalized = _normalized(_ADR_FILES[0])
    assert "`InboundEventNormalizer`" in document
    assert "`InboundEventSchema`" in document
    assert "schema is the allowlisting boundary" in normalized
    assert "external caller cannot choose the internal Event Bus event name" in normalized
    assert "Raw request bodies are never published directly" in document


def test_authentication_adr_records_exact_modes_and_atomic_idempotency() -> None:
    document = _read(_ADR_FILES[1])
    normalized = _normalized(_ADR_FILES[1])
    assert "`InboundHmacPolicy`" in document
    assert "`InboundServiceAccountPolicy`" in document
    assert "`inbound_event.submit`" in document
    assert "exact versioned `SecretRef`" in normalized
    assert "atomically reserves replay and source-event identities" in normalized
    assert "same stable receipt" in document
    assert "generic public errors" in document


def test_listener_adr_records_shared_exact_fail_closed_routing() -> None:
    document = _read(_ADR_FILES[2])
    normalized = _normalized(_ADR_FILES[2])
    assert "creates no second socket" in normalized
    assert "/v1/control-plane/inbound/<source-name>" in document
    assert "enabling a source adds its exact route" in document
    assert "disabling or revoking a source removes its route" in document
    assert "before reading the request body" in normalized
    assert "trusted RFC-0023 transport context" in document


def test_publication_adr_records_durable_acceptance_and_at_least_once() -> None:
    document = _read(_ADR_FILES[3])
    normalized = _normalized(_ADR_FILES[3])
    assert "success response and stable receipt are returned only after" in normalized
    assert "Publication is asynchronous and at-least-once" in document
    assert "one immutable ordered attempt history" in document
    assert "never resets counters or rewrites history" in document
    assert "Internal Event Bus consumers must be idempotent" in normalized


def test_runtime_adr_records_opt_in_ownership_and_security_separation() -> None:
    document = _read(_ADR_FILES[4])
    normalized = _normalized(_ADR_FILES[4])
    assert "disabled by default" in document
    assert "coordinated source, accepted-event, and replay repository trio" in normalized
    assert "Startup order is explicit" in document
    assert "Runtime reverse shutdown" in document
    assert "Human administration" in document
    assert "Machine administration" in document
    assert "Source submission authority is independent from administration" in normalized


def test_inbound_adrs_do_not_contain_secret_examples_or_unsafe_advice() -> None:
    joined = "\n".join(_read(name) for name in _ADR_FILES)
    forbidden = (
        'secret = "',
        'password = "',
        'api_key = "',
        "allow_insecure_loopback=True",
        "publish raw request bodies",
        "grant `*`",
    )
    for phrase in forbidden:
        assert phrase not in joined

    normalized = " ".join(joined.split())
    assert "unrestricted raw bodies remain outside ordinary persistence" in normalized
    assert "Machine administration is a separate optional flag" in joined
    assert "no second socket" in normalized


def test_readme_and_rfc_link_the_inbound_adr_collection() -> None:
    readme = _README.read_text(encoding="utf-8")
    rfc = _RFC.read_text(encoding="utf-8")
    assert "docs/adrs/README.md" in readme
    assert "RFC-0025 inbound records cover" in readme
    assert "- [x] Architecture Decision Records" in rfc
    for name in _ADR_FILES:
        assert name in rfc
