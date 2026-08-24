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


def test_rfc0034_slice3_adds_generation_bound_network_authority_without_tool_inheritance() -> None:
    text = _RFC.read_text(encoding="utf-8")
    normalized = " ".join(text.split())

    assert "## Slice 3 canonical network authority" in text
    assert "`network-egress:<profile-id>/generation:<generation>/operation:<operation-id>`" in text
    assert "The request body enters the intent only through its exact `body_digest`" in normalized
    assert (
        "Plaintext secret material is never hashed into or attached to the authority intent."
        in normalized
    )
    assert (
        "A successful authorization is a point-in-time decision, not a bearer capability."
        in normalized
    )
    assert "generic `SecurityContext.confirmed` flag is cleared" in normalized
    assert "`tool.invoke -> network.http.request` is not added in Slice 3." in normalized
    assert (
        "Slice 3 performs no DNS resolution, socket connection, secret lease, or HTTP send."
        in normalized
    )


def test_rfc0034_slice4_revalidates_after_pinned_connect_without_retry_or_queue() -> None:
    text = _RFC.read_text(encoding="utf-8")
    normalized = " ".join(text.split())

    assert "## Slice 4 network service, final freshness, and TOCTOU closure" in text
    assert "exactly two `network.http.request` authorizations" in normalized
    assert "connect TCP/TLS only to one admitted literal without writing HTTP bytes" in normalized
    assert "revalidate exact SecretLease when required" in normalized
    assert "validate current RFC-0033 subject freshness again" in normalized
    assert "Current profile validation compares the complete immutable profile" in normalized
    assert "Service concurrency is finite and has no request queue in Slice 4." in normalized
    assert (
        "Any failure or timeout once request bytes may have started is `INDETERMINATE`."
        in normalized
    )
    assert "never transparently retries an indeterminate remote effect" in normalized
    assert "Final trusted validation follows RFC-0033 source-specific freshness semantics." in (
        normalized
    )
    assert "does not claim one atomic snapshot" in normalized
    assert "Slice 4 adds no `tool.invoke -> network.http.request` mediated transition" in normalized


def test_rfc0034_slice5_composes_tool_and_network_authority_without_ssrf_controls() -> None:
    text = _RFC.read_text(encoding="utf-8")
    normalized = " ".join(text.split())

    assert "## Slice 5 controlled tool composition and adversarial SSRF closure" in text
    assert "`tool.invoke -> network.http.request`" in normalized
    assert "composition metadata, not authority inheritance" in normalized
    assert "must satisfy both boundaries as an intersection" in normalized
    assert "one complete immutable egress profile including generation" in normalized
    assert "The model cannot select a URL, scheme, host, port, method, path, proxy" in normalized
    assert "only as canonical base64 under the single `body_base64` field" in normalized
    assert "limited to 196608 raw bytes" in normalized
    assert "rejected before DNS" in normalized
    assert (
        "server-owned final-admission validator rather than a reusable ALLOW decision" in normalized
    )
    assert "while the session has written zero HTTP request bytes" in normalized
    assert "Adapters that require final admission cannot execute through the legacy" in normalized
    assert "Any failure after request bytes may have started remains `INDETERMINATE`" in normalized
    assert "no generic URL fetch, raw socket API, browser navigation" in normalized
