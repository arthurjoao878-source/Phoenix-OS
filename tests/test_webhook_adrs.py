from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_ADRS = _ROOT / "docs" / "adrs"
_INDEX = _ADRS / "README.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0024-durable-signed-webhooks-and-event-subscriptions.md"
_README = _ROOT / "README.md"

_ADR_FILES = (
    "ADR-0001-explicit-webhook-serializers-and-durable-envelopes.md",
    "ADR-0002-versioned-webhook-signing-keys.md",
    "ADR-0003-fail-closed-webhook-egress.md",
    "ADR-0004-bounded-webhook-retry-and-redrive.md",
    "ADR-0005-opt-in-webhook-runtime-and-administration.md",
)


def _read(name: str) -> str:
    return (_ADRS / name).read_text(encoding="utf-8")


def test_webhook_adr_index_links_every_record() -> None:
    index = _INDEX.read_text(encoding="utf-8")
    for name in _ADR_FILES:
        assert name in index


def test_webhook_adrs_use_complete_accepted_structure() -> None:
    for name in _ADR_FILES:
        document = _read(name)
        assert "- **Status:** Accepted" in document
        assert "- **Date:** 2026-07-24" in document
        assert "## Context" in document
        assert "## Decision" in document
        assert "## Consequences" in document
        assert "## Alternatives considered" in document
        assert "## Supersession criteria" in document


def test_serializer_adr_records_allowlisting_and_stability() -> None:
    document = _read(_ADR_FILES[0])
    assert "`WebhookPayloadSerializer`" in document
    assert "internal Event Bus payloads are not external contracts" in document
    assert "canonical body" in document
    assert "(subscription_id, source_event_id)" in document


def test_signing_adr_records_exact_versioned_secret_selection() -> None:
    document = _read(_ADR_FILES[1])
    assert "`hmac-sha256-v1`" in document
    assert "exact versioned `SecretRef`" in document
    assert "clears the temporary key byte buffer" in document
    assert "revokes the secret lease" in document


def test_egress_adr_records_per_attempt_ssrf_boundary() -> None:
    document = _read(_ADR_FILES[2])
    assert "resolve the hostname again for the current attempt" in document
    assert "every resolved address" in document
    assert "literal address" in document
    assert "does not follow redirects" in document
    assert "ambient proxy behavior" in document


def test_retry_adr_records_global_history_and_redrive() -> None:
    document = _read(_ADR_FILES[3])
    normalized = " ".join(document.split())

    assert "one global bounded attempt budget" in normalized
    assert "never resets counters or rewrites history" in document
    assert "`webhook.delivery.redrive`" in document
    assert "same business delivery" in normalized


def test_runtime_adr_records_opt_in_and_security_separation() -> None:
    document = _read(_ADR_FILES[4])
    assert "disabled by default" in document
    assert "Startup order is explicit" in document
    assert "Human administration" in document
    assert "Machine administration" in document
    assert "does not implicitly enable" in document


def test_adrs_do_not_contain_secret_examples_or_insecure_production_advice() -> None:
    joined = "\n".join(_read(name) for name in _ADR_FILES)
    forbidden = (
        'secret = "',
        'password = "',
        'api_key = "',
        "allow_insecure_loopback=True",
    )
    for phrase in forbidden:
        assert phrase not in joined

    assert "does not follow redirects" in joined
    assert "private and local network authority must be explicit" in joined


def test_readme_and_rfc_link_the_adr_collection() -> None:
    readme = _README.read_text(encoding="utf-8")
    rfc = _RFC.read_text(encoding="utf-8")
    assert "docs/adrs/README.md" in readme
    assert "- [x] Architecture Decision Records" in rfc
    for name in _ADR_FILES:
        assert name in rfc
