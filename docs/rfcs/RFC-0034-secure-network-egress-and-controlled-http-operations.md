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

## Slice 2 transport boundary

Slice 2 separates destination resolution/admission, pinned connection establishment, and
the one-shot HTTP exchange so that later slices can place fresh authority checks at the
correct boundary.

The sequence is:

```text
resolve canonical server-owned host
    -> validate the complete DNS answer set
    -> pin immutable literal addresses
    -> connect TCP/TLS to one admitted literal
    -> return a connected session without sending HTTP bytes
    -> later final freshness/authority admission
    -> one-shot HTTP exchange
```

Opening a pinned session MUST NOT write HTTP request bytes. The connected session may be
closed without sending a request when later freshness, cancellation, profile-generation,
or authority checks fail.

Before any request byte may have been written, the connector may fall back among the
already-admitted pinned literals. After a request write may have started, the session is
one-shot: it performs no reconnect, alternate-address fallback, or transparent retry.

The direct connector uses numeric destination addresses only. Hosted HTTPS retains the
canonical profile host for TLS SNI and certificate verification, requires TLS 1.2 or
newer, and offers only HTTP/1.1 through ALPN. Loopback HTTP uses no TLS hostname.
Ambient HTTP proxy variables are not consulted because Slice 2 uses no ambient HTTP
client or proxy stack.

Automatic public-network admission also rejects known IPv4-transition/tunnel IPv6
prefixes such as IPv4-compatible, NAT64 well-known/local-use, Teredo, and 6to4. These
destinations require a trusted explicit `allowed_networks` CIDR; an apparently global
transition address does not gain destination authority merely from `is_global`.

Automatic public admission is additionally protected by Phoenix-owned conservative
special-use IPv4/IPv6 deny ranges rather than trusting the host Python point release's
`ipaddress.is_global` classification as the sole security decision. Legacy site-local,
documentation, benchmarking, shared, translation, loopback/link-local, multicast,
reserved, and other reviewed special-use ranges require an explicit trusted
`allowed_networks` CIDR. Explicit CIDRs remain the server-owned opt-in for deliberately
configured non-public destinations.

The HTTP/1.1 parser enforces finite status-line, header-count, header-byte, and body
limits. Connection teardown waits are bounded as well; remote close behavior cannot
create an unbounded post-exchange wait. Ambiguous `Content-Length` plus
`Transfer-Encoding`, duplicate headers, unsupported transfer encodings, protocol
upgrade, chunk extensions, and response trailers fail closed. Redirect responses are
returned only as bounded untrusted data and never trigger another request.

No DNS lookup, proxy selection, redirect handling, or alternate-address fallback occurs
after HTTP request bytes may have been written.

Slice 2 does not add `network.http.request` to the authority catalog and does not claim
that a connected socket is authority. Slice 3 introduces the canonical network
authorizer. Slice 4 owns secret leasing plus final subject/profile/cancellation/freshness
revalidation immediately before the protected send. Existing webhook and inference
transports remain unchanged and independently authoritative.

## Slice 3 canonical network authority

Slice 3 adds `network.http.request` to the RFC-0033 closed-world authority catalog.
The canonical resource is generation-bound and operation-specific:

`network-egress:<profile-id>/generation:<generation>/operation:<operation-id>`

The profile ID, positive profile generation, and operation ID are server-owned identifiers.
The hostname, URL-like request target, request body, DNS answers, and credential material do
not become canonical authority resources.

Each authorization builds an exact `AuthorityIntent`. Its parameter digest uses deterministic
length-framed fields covering the selected profile, destination mode and configured host/port,
explicit network policy, exact operation method/target/effect/limits, server-owned media/header
configuration, request identity/timestamp, and request-body metadata. The request body enters
the intent only through its exact `body_digest`; raw body bytes are never included in policy
resources or authority observations.

Credential configuration contributes only the reviewed header binding plus the exact
versioned `SecretRef` identity and non-secret fixed prefix. Plaintext secret material is never
hashed into or attached to the authority intent.

The intent carries a `network.profile.generation` freshness binding in addition to the
generation present in the canonical resource. A policy grant for one generation therefore
does not authorize a later profile generation merely because profile and operation IDs are
unchanged.

The canonical authorizer requires the authenticated requester context and submits the exact
`network.http.request` action/resource to `PolicyEngine`. The generic `SecurityContext.confirmed`
flag is cleared for this boundary so an unrelated ambient confirmation cannot satisfy network
authority. Policy rejection, confirmation requirements, catalog mismatch, stale operation
binding, profile mismatch, and operation-specific body-limit mismatch fail closed through one
content-free authorization error.

A successful authorization is a point-in-time decision, not a bearer capability. Slice 4 must
resolve current server-owned profile state and perform the required final freshness,
cancellation, and authority revalidation after the final attacker-controlled wait and before
the protected send.

`tool.invoke -> network.http.request` is not added in Slice 3. Tool authorization therefore
does not inherit or manufacture network authority. Any reviewed mediated tool-to-network
transition is deferred to Slice 5 together with the bounded tool facade and confused-deputy
tests.

Slice 3 performs no DNS resolution, socket connection, secret lease, or HTTP send.

## Slice 4 network service, final freshness, and TOCTOU closure

Slice 4 introduces the `NetworkEgressService` that composes the server-owned profile,
RFC-0033 authority, Secrets Vault, Slice 2 destination admission, and the pinned
transport. It does not make a connected socket a bearer capability and it does not
expose the internal transport or destination-admission objects as public authority.

One admitted service attempt follows this order:

```text
resolve current profile + exact operation
    -> apply finite no-queue concurrency admission
    -> check cooperative cancellation and effective deadline
    -> validate current RFC-0033 subject freshness
    -> authorize exact network.http.request intent
    -> lease the exact configured SecretRef when required
    -> resolve DNS once and admit the complete answer set
    -> pin immutable literal addresses
    -> connect TCP/TLS only to one admitted literal without writing HTTP bytes
    -> revalidate exact SecretLease when required
    -> validate current RFC-0033 subject freshness again
    -> authorize the exact network.http.request intent again
    -> synchronously revalidate cancellation, deadline, current full profile/operation,
       and the pinned destination admission
    -> reveal credential bytes only at the final transport boundary
    -> immediately perform the one-shot HTTP exchange
```

The service performs exactly two `network.http.request` authorizations: one before DNS
or connection work, and one after the final attacker-controlled network wait. A
successful earlier decision is never reused as bearer authority for the protected send.

Current profile validation compares the complete immutable profile and exact operation,
not only the generation number. A generation, destination, network-policy, method,
request-target, credential-reference, media/header configuration, effect, or limit
change rejects the attempt. The already pinned address set is re-admitted against the
same current profile immediately before the protected send.

Credential leasing uses the original requester `SecurityContext`; the service never
substitutes a stronger service or system principal. The lease TTL cannot exceed the
remaining effective request deadline. After the pinned connection is established, the
exact lease is resolved again for the same principal before final subject freshness and
network authorization. Plaintext secret material is revealed only synchronously at the
last transport boundary. The fixed credential prefix remains transport-owned.

The effective deadline is the minimum of the caller-supplied deadline, when present,
and the operation's total timeout measured from a server-owned invocation time. Caller
request timestamps are not trusted as security clocks. Cooperative cancellation may
stop work before the protected send. After request bytes begin, cooperative
cancellation does not trigger reconnect or transparent retry.

Service concurrency is finite and has no request queue in Slice 4. Saturation rejects
immediately before DNS, secret material use, connection establishment, or request
bytes. Queueing and Runtime lifecycle ownership are intentionally deferred rather than
creating another attacker-controlled wait in the final admission path.

Failures are content-minimized. Authority, freshness, profile, secret, destination, and
saturation rejection produce a sanitized `REJECTED` result class; cooperative
pre-send cancellation produces `CANCELLED`; pre-send deadline expiry produces
`TIMED_OUT`; and a transport failure known to occur before request bytes produces
`FAILED`. Any failure or timeout once request bytes may have started is
`INDETERMINATE`. The service never transparently retries an indeterminate remote
effect.

Final trusted validation follows RFC-0033 source-specific freshness semantics. Slice 4
does not claim one atomic snapshot spanning policy, identity/session state, Secrets
Vault lease state, and profile state. A revocation or policy change that linearizes
before that source's final revalidation rejects the attempt; a change that linearizes
after that source's final revalidation is not reported as a fictitious rollback merely
because another trusted Phoenix source is validated later in the same admission
sequence.

Slice 4 adds no `tool.invoke -> network.http.request` mediated transition, no general
tool facade, no webhook or inference migration, and no Runtime lifecycle,
observability, or operator surface. Those remain later-slice responsibilities.

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
