# RFC-0034: Secure Network Egress and Controlled HTTP Operations

- Status: Draft
- Target release: Phoenix OS v0.34.0
- Owners: Phoenix OS maintainers
- Architecture freeze: 2026-08-23
- Depends on: RFC-0002, RFC-0003, RFC-0004, RFC-0005, RFC-0006, RFC-0009,
  RFC-0010, RFC-0011, RFC-0012, RFC-0024, RFC-0026, RFC-0027, and RFC-0033

## Summary

RFC-0034 defines an optional, fail-closed, policy-controlled network-egress boundary for
Phoenix OS. The initial release supports controlled HTTP operations through
server-owned egress profiles. A caller selects only stable Phoenix-owned profile and
operation identifiers; it never supplies an arbitrary URL, host, port, proxy, DNS
resolver, TLS policy, redirect policy, credential, or raw socket target.

The subsystem is a new canonical protected-operation boundary. It does not replace the
existing webhook or inference authorizers, transports, or endpoint policies. Those
subsystems remain independently authoritative until a later change proves behavioral
and security equivalence.

The design preserves RFC-0033 capability non-amplification:

> **Remote data is data. Network effects require fresh, exact, server-owned authority.**

and:

> **Every protected operation remains dominated by its canonical authority boundary,
> regardless of how that operation is reached.**

## Motivation

Phoenix OS already contains specialized outbound-network behavior for signed webhook
delivery and configured model providers. Those paths intentionally solve narrow
problems and deliberately do not provide a general-purpose HTTP client.

Agent tooling, later browser automation, and future integrations need an explicit
network boundary rather than ad-hoc HTTP calls. Without such a boundary, model output
could select arbitrary destinations, exploit SSRF, smuggle authority through redirects,
inherit ambient proxy configuration, expose credentials, or use one subsystem's
network access as a confused deputy.

RFC-0034 therefore introduces a controlled egress substrate whose authority is narrower
than general Internet access.

## Principle

A network request is admitted from current trusted Phoenix state, not from the fact that
a string happens to contain a URL.

The model or caller may provide request data only within a preconfigured operation. The
destination identity, HTTP method, request target, credential binding, response exposure,
and finite limits are server-owned configuration.

A response is untrusted data. It grants no authority to follow another URL, invoke a
tool, mutate memory or workspace state, perform a host action, or execute browser
behavior.

## Goals

- Optional network egress disabled by default
- Stable server-owned egress profile and operation identifiers
- Immutable finite profile definitions
- Exact controlled HTTP method and request target per operation
- No caller-selected arbitrary URL, host, port, scheme, proxy, or redirect behavior
- Verified HTTPS for hosted destinations
- Explicit loopback-only HTTP mode for local development/integration targets
- DNS resolution followed by fail-closed address admission and literal destination pinning
- SSRF-resistant public/private/loopback/link-local destination policy
- Fresh exact `network.http.request` authorization
- RFC-0033 subject, intent, resource, freshness, and non-amplification preservation
- Exact body digest binding for request intent
- Bounded request and response bodies, headers, DNS answers, duration, and concurrency
- Versioned Secrets Vault references for optional credentials
- No plaintext credential exposure to caller, model, logs, audit, metrics, or result data
- No transparent redirect following
- No ambient proxy behavior
- Cooperative cancellation and finite deadlines
- Content-minimized safe observability
- Runtime-owned finite lifecycle
- Deterministic fakes and adversarial security tests
- Compatibility with Phoenix OS v0.33.0 by omission

## Non-goals

- Arbitrary URL fetching
- A general-purpose `requests`, `urllib`, or browser-like client API
- Raw TCP, UDP, QUIC, ICMP, or Unix-domain socket authority
- Caller-selected DNS servers or DNS-over-HTTPS endpoints
- Caller-selected proxies, HTTP CONNECT tunnels, VPNs, or SOCKS
- Automatic redirects
- HTTP TRACE, CONNECT, protocol upgrade, or generic WebSocket support
- Browser automation
- Cookie jars, browser sessions, DOM state, JavaScript execution, forms, or navigation
- Automatic downloads into agent workspaces
- Arbitrary uploads from the host filesystem
- Replacing webhook delivery or model-provider authorization
- Automatically migrating webhook or inference transport to the new subsystem
- Exactly-once guarantees for remote effects
- Transparent retry after a potentially effectful request begins
- Treating HTTP success as proof that returned data is safe
- Treating a response-provided URL as authority for a second request
- A hostile-code sandbox for installed network adapters

## Terminology

- **Egress profile:** immutable server-owned description of one network destination and
  the controlled operations available at that destination.
- **Profile ID:** stable Phoenix-owned identifier for an egress profile.
- **Profile generation:** positive server-owned version used to distinguish changed
  profile definitions.
- **Operation ID:** stable Phoenix-owned identifier for one controlled HTTP operation.
- **Request target:** exact server-owned HTTP origin-form path and optional query for one
  operation. It is not supplied by the caller. It uses visible ASCII only; spaces and
  non-ASCII UTF-8 bytes require explicit percent-encoding.
- **Network request:** bounded caller data referencing only profile ID, operation ID, and
  optional request body.
- **Remote effect:** externally observable action that may occur after bytes are sent.
- **Resolved destination:** canonical profile destination plus the admitted literal IP
  addresses for one attempt.
- **Pinned connection:** connection made to one already admitted literal IP while
  preserving the canonical TLS server name.
- **Network response:** bounded untrusted data returned by the remote peer.

## Architecture

```text
Agent / caller
    |
    +-- tool.invoke boundary when model-originated
    |
    +-- NetworkEgressService
           |
           +-- resolve current server-owned profile + operation
           +-- exact request/body intent
           +-- RFC-0033 current-subject freshness
           +-- network.http.request authorization
           +-- destination DNS/IP admission
           +-- cancellation/deadline revalidation
           |
           +-- NetworkTransport
                  |
                  +-- literal-address TCP/TLS connection
                  +-- bounded HTTP/1.1 exchange
```

The public request does not contain a URL. The operation fixes the method and request
target. The profile fixes host, port, destination mode, network policy, credentials, and
finite limits.

## Authority model

The canonical action introduced by this RFC is:

```text
network.http.request
```

The intended canonical resource grammar is:

```text
network-egress:<profile-id>/generation:<generation>/operation:<operation-id>
```

The resource will be added to the RFC-0033 closed-world authority catalog in Slice 3,
not Slice 1. Slice 1 intentionally establishes only the data/configuration contracts.

For a model-originated request:

```text
effective authority
    =
tool.invoke
    INTERSECT
network.http.request
    INTERSECT
current principal/session/agent/run
    INTERSECT
current policy
    INTERSECT
exact profile generation
    INTERSECT
exact operation
    INTERSECT
exact body digest
    INTERSECT
current destination admission
    INTERSECT
cancellation/deadline state
```

No upstream allow can substitute for the final network boundary.

## Server-owned profiles

A profile contains:

- stable `NetworkEgressProfileId`;
- positive generation;
- canonical destination mode;
- canonical host and port;
- public-network and explicit-network admission policy;
- one or more `NetworkEgressOperation` definitions;
- optional exact-version secret-header credential binding.

An operation contains:

- stable `NetworkEgressOperationId`;
- HTTP method from the reviewed finite method set;
- exact server-owned request target;
- trusted effect classification;
- finite operation limits;
- optional server-owned `Accept` and `Content-Type` values;
- explicit allowlist of response headers that may be exposed.

Callers cannot add headers. In particular they cannot choose `Host`, `Authorization`,
`Cookie`, forwarding headers, connection framing, transfer encoding, proxy behavior, or
TLS configuration.

## Request body

A caller may supply bounded bytes only when the selected operation permits a non-zero
request body.

The public request exposes a deterministic SHA-256 digest of its exact body. Later
authorization/admission slices bind the exact request intent to this digest. Changing
the body changes the intent.

The body is data, not authority.

## Credentials

An optional credential binding references one exact versioned `SecretRef`. The binding
selects a reviewed HTTP header name and a non-secret fixed prefix such as `Bearer `.

Secret material is leased only for one admitted execution in a later slice. Plaintext
secret bytes never become part of the public request, response, profile representation,
logs, errors, audit details, or persisted operation state.

Credentials do not grant destination authority. Destination authority does not grant
credential authority.

## Destination admission

Slice 2 will implement the following requirements:

1. Parse only the already canonical server-owned host and port.
2. Resolve with a reviewed Phoenix resolver.
3. Bound the number of DNS answers.
4. Parse every answer as a literal IP address.
5. Reject the complete resolution set if any answer violates the active profile policy.
6. Pin the admitted literal addresses for the attempt.
7. Connect only to a pinned literal address.
8. For hosted HTTPS, retain the canonical hostname for TLS SNI/certificate validation.
9. Never use ambient proxy configuration.
10. Never follow redirects.

A DNS answer is data. It does not widen the configured destination policy.

## Redirects

Redirect following is not supported by Phoenix OS v0.34.0.

A 3xx response is returned as bounded untrusted response data. A `Location` header is
not automatically exposed and never causes a second request. A future redirect feature
would require a separate reviewed authority contract and destination re-admission.

## Security invariants

1. Network egress is disabled unless explicitly configured.
2. Enabling network egress grants no permission, approval, credential, request, socket, browser, workspace, host, or tool authority automatically.
3. Every egress profile has a stable server-owned profile ID.
4. Every egress profile has a positive server-owned generation.
5. Every controlled operation has a stable server-owned operation ID.
6. Public requests select only profile ID and operation ID; they never contain a URL.
7. Callers cannot select scheme, host, port, DNS resolver, proxy, TLS policy, redirect policy, credential, or literal destination address.
8. The HTTP method is fixed by the selected server-owned operation. A `READ_ONLY`
   effect classification is valid only for `GET` or `HEAD`; every other reviewed
   method requires `REMOTE_EFFECT`. `GET` and `HEAD` may still be conservatively
   classified as `REMOTE_EFFECT`.
9. The HTTP request target is fixed by the selected server-owned operation and uses
   canonical visible ASCII origin-form; spaces and non-ASCII bytes require explicit
   percent-encoding.
10. Request bodies are bounded data and are bound by an exact SHA-256 digest.
11. Callers cannot add arbitrary HTTP headers. Server-owned header material is validated
    before transport use: media types use printable ASCII token grammar, and credential
    value prefixes use printable ASCII only.
12. `Host`, framing, transfer, proxy, forwarding, cookie, and credential headers are never caller-controlled.
13. Optional credential material comes only from an exact-version `SecretRef`.
14. Plaintext credentials never enter public request/response contracts or routine telemetry.
15. Hosted remote destinations require verified HTTPS.
16. Plain HTTP is supported only by an explicitly configured loopback mode.
17. DNS answers are bounded and every returned address must pass the active destination policy.
18. A rejected DNS answer rejects the attempt; unsafe answers are not silently discarded to continue with safe ones.
19. Connection attempts use only previously admitted literal destination addresses.
20. Hosted TLS validates the canonical configured hostname, not attacker-provided response data.
21. Ambient HTTP proxy and environment proxy configuration are ignored.
22. Redirects are not followed.
23. HTTP CONNECT, TRACE, upgrade, generic WebSocket, and raw socket authority are outside v0.34.0.
24. Every request requires fresh exact `network.http.request` authorization before the remote effect.
25. `tool.invoke` authorization does not imply `network.http.request`.
26. `network.http.request` does not imply `tool.invoke`, `model.infer`, webhook, memory, workspace, host, browser, or any other authority.
27. Effective authority is the intersection of all currently valid constraints, never their union.
28. Internal services cannot replace the requester with a stronger subject.
29. Current principal/session/agent/run state is revalidated after the final attacker-controlled wait.
30. Current profile generation and operation identity are revalidated after the final attacker-controlled wait.
31. Current DNS/IP destination admission is revalidated before connection after any untrusted wait that invalidates it.
32. Cancellation and deadlines are revalidated before effect admission.
33. No new attacker-controlled blocking wait occurs between final admission and the protected send without repeating the applicable freshness checks.
34. Network response status, headers, and body are untrusted data and never authority.
35. Response data cannot manufacture another network request or other protected operation.
36. Cookie storage and `Set-Cookie` exposure are outside v0.34.0.
37. Request, response, header, address-count, timeout, and concurrency limits are finite.
38. Potentially effectful requests receive no transparent retry after request bytes may have been sent.
39. Existing webhook and inference canonical authorizers remain independently authoritative.
40. RFC-0034 does not silently reroute webhook or inference transport through this subsystem.
41. New mediated tool-to-network transitions require RFC-0033 closed-world catalog review.
42. Unknown in-scope network operations fail closed.
43. Observability excludes request/response bodies, credentials, unrestricted headers, and resolved private addresses by default.
44. Browser automation remains outside this RFC.
45. Existing Phoenix OS v0.33.0 behavior is unchanged when network-egress configuration is absent.

## Slice plan

### Slice 1 — Contracts and server-owned profiles

- RFC architecture freeze
- immutable identifiers, request/response contracts, and body digest
- immutable operation/profile definitions
- exact-version secret-header credential binding
- finite profile catalog
- targeted contract/profile/RFC tests

No authorization, socket, DNS query, network request, Runtime mutation, or external effect
is introduced by Slice 1.

### Slice 2 — Destination admission and pinned HTTP transport

- resolver and literal-address normalization
- public/private/loopback destination policy
- DNS rebinding-resistant admission
- pinned TCP/TLS connection
- bounded HTTP/1.1 exchange
- redirect rejection and no ambient proxy behavior
- deterministic resolver/connector fakes

### Slice 3 — Canonical network authority

- `network.http.request` authorizer
- canonical resource including profile generation and operation
- exact request/body intent binding
- RFC-0033 closed-world catalog integration
- tool-to-network mediated transition declaration only where reviewed

### Slice 4 — NetworkEgressService and freshness

- profile resolution
- secret leasing
- cancellation/deadline handling
- final freshness and destination revalidation
- finite admission/concurrency
- safe result/error mapping

### Slice 5 — Tool composition and adversarial security

- bounded agent-tool facade
- confused-deputy and cross-agent resistance
- SSRF, DNS rebinding, redirect, Host/header, credential, stale-profile, cancellation,
  and authority-laundering adversarial tests

### Slice 6 — Runtime and observability

- optional Runtime composition
- lifecycle ownership and drain
- content-free audit/metrics/health
- redaction and inspection guarantees

### Slice 7 — Release closure

- dedicated network release gate
- complete regression suite
- migration guidance
- threat-model/security-invariant review
- package-boundary verification
- v0.34.0 release notes and publication evidence
- exact Python 3.12/3.13 CI

## Compatibility

Phoenix OS v0.34.0 creates no network-egress service when configuration is omitted.
Existing webhooks and model providers retain their existing boundaries and behavior.

No existing permission is interpreted as `network.http.request`.

## Browser relationship

Browser automation is intentionally deferred. A future browser RFC must not treat this
RFC as ambient Internet authority. Browser navigation and browser session state require
their own canonical authority boundary and must compose with network authority without
amplification.

## Acceptance

RFC-0034 remains Draft until all seven slices, adversarial review, dedicated release
gate, package verification, and the exact release CI matrix pass. Acceptance requires
evidence that every Phoenix-mediated network effect remains dominated by the canonical
network authority boundary regardless of whether it is reached directly or through an
agent/tool composition.
