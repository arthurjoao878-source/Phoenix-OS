from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0034-secure-network-egress-and-controlled-http-operations.md"


def test_rfc0034_is_draft_for_v034_and_names_the_canonical_network_action() -> None:
    text = _RFC.read_text(encoding="utf-8")

    assert "- Status: Draft" in text
    assert "- Target release: Phoenix OS v0.34.0" in text
    assert "network.http.request" in text
    assert "spaces and non-ASCII bytes require explicit" in text
    assert "effect classification is valid only for `GET` or `HEAD`" in text
    assert "method requires `REMOTE_EFFECT`" in text
    assert "media types use printable ASCII token grammar" in text
    assert "credential value prefixes use printable ASCII only" in " ".join(text.split())
    assert (
        "Remote data is data. Network effects require fresh, exact, server-owned authority." in text
    )


def test_rfc0034_keeps_network_and_browser_authority_separate() -> None:
    text = _RFC.read_text(encoding="utf-8")

    assert "Browser automation remains outside this RFC." in text
    assert "Browser navigation and browser session state require" in text
    assert "their own canonical authority boundary" in text


def test_rfc0034_preserves_existing_webhook_and_inference_boundaries() -> None:
    text = _RFC.read_text(encoding="utf-8")

    assert (
        "Existing webhook and inference canonical authorizers remain independently authoritative."
        in text
    )
    assert "RFC-0034 does not silently reroute webhook or inference transport" in text


def test_rfc0034_slice1_is_non_networking_and_non_authoritative() -> None:
    text = _RFC.read_text(encoding="utf-8")

    assert (
        "No authorization, socket, DNS query, network request, Runtime mutation, or external effect"
        in text
    )
    assert (
        "The resource will be added to the RFC-0033 closed-world authority catalog in Slice 3"
        in text
    )


def test_rfc0034_slice2_separates_connect_from_protected_http_send() -> None:
    text = _RFC.read_text(encoding="utf-8")

    assert "Opening a pinned session MUST NOT write HTTP request bytes." in text
    assert (
        "No DNS lookup, proxy selection, redirect handling, or alternate-address fallback occurs"
        in text
    )
    assert "after HTTP request bytes may have been written." in text
    assert "Slice 2 does not add `network.http.request` to the authority catalog" in text
    assert "Slice 4 owns secret leasing plus final subject/profile/cancellation/freshness" in text
    assert "Ambient HTTP proxy variables are not consulted" in text
    assert "Connection teardown waits are bounded as well" in text
    assert "apparently global" in text
    assert "transition address does not gain destination authority" in text
    assert "Phoenix-owned conservative" in text
    assert "`ipaddress.is_global` classification as the sole security decision" in text
