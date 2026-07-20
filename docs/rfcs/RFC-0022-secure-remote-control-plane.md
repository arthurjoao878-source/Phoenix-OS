# RFC-0022: Secure Remote Control Plane and TLS

- Status: Accepted
- Target release: Phoenix OS v0.22.0
- Owners: Phoenix OS maintainers

## Summary

Phoenix OS currently exposes the Control Plane only through literal loopback addresses. RFC-0022 defines a fail-closed path to optional remote administration with native TLS, optional mutual TLS, explicit public-origin binding, client-network allowlists, trusted-proxy handling, per-client resource bounds, and safe operational health data.

Remote exposure remains opt-in. Existing installations continue to use loopback-only HTTP unless an operator supplies a complete remote policy.

## Security invariants

1. Remote exposure requires native TLS and an HTTPS public origin.
2. Dashboard cookies are `Secure` whenever the public origin is HTTPS.
3. Certificate, private-key, and client-CA paths are absolute and validated as a coherent TLS mode.
4. Private-key contents and paths are excluded from safe snapshots.
5. Client addresses are canonical IP literals with explicit provenance.
6. Proxy headers are ignored unless exactly one supported format is enabled and the peer belongs to an explicit trusted-proxy network.
7. Client and proxy networks use canonical, unique CIDR notation.
8. Loopback mode cannot bind wildcard or non-loopback addresses and cannot allow non-loopback clients.
9. Remote mode requires an explicit port and non-loopback public origin.
10. Configuration ambiguity fails closed before the listener starts.

## Slice plan

### Slice 1 — Network, TLS, origin, and identity contracts

- [x] Exposure modes for loopback and remote operation
- [x] Native TLS modes for disabled, server-authenticated, and mutual TLS
- [x] Allowlisted minimum TLS versions
- [x] Absolute certificate-material references with private-key redaction
- [x] Canonical browser public-origin contract
- [x] Canonical client and trusted-proxy CIDR allowlists
- [x] Explicit `Forwarded` or `X-Forwarded-For` policy
- [x] Canonical client identity and provenance contract
- [x] Per-client connection bound
- [x] Non-sensitive network and TLS snapshots
- [x] Fail-closed cross-field validation

### Slice 2 — TLS listener and certificate lifecycle

- [x] Native hardened `ssl.SSLContext` construction
- [x] Certificate/key loading with bounded regular-file and permission checks
- [x] Typed material, reload, context-state, and listener-state failures
- [x] TLS 1.2 or TLS 1.3 minimum-version enforcement
- [x] HTTP/1.1 ALPN and compression, renegotiation, and ticket hardening
- [x] Optional required client-certificate verification for mutual TLS
- [x] Bounded TLS handshake and shutdown timeouts
- [x] Post-handshake connection capacity and lifecycle accounting
- [x] Certificate fingerprint, validity, subject, issuer, and expiry health
- [x] Safe snapshots without certificate paths or private-key material
- [x] Atomic certificate reload for new handshakes without rebinding the socket
- [x] Failed reload preservation of the previously active context

### Slice 3 — Remote client resolution and abuse controls

- [x] Strict Host validation
- [x] Exact public-origin validation
- [x] Direct client identity resolution
- [x] Trusted `Forwarded` parsing
- [x] Trusted `X-Forwarded-For` parsing
- [x] Spoofed proxy-header rejection
- [x] Client-network allowlist enforcement
- [x] Per-client connection and request rate limits

### Slice 4 — Remote authentication, cookies, CSRF, and audit

- [x] `Secure` cookie enforcement
- [x] Public-origin-bound CSRF
- [x] Remote login throttling by client and operator
- [x] Connection, authentication, allowlist, and block audit events
- [x] Safe remote-address representation
- [x] Dashboard HTTPS compatibility

### Slice 5 — Runtime integration and v0.22.0

- [x] RuntimeAssembler exposure-policy wiring
- [x] Listener lifecycle and health snapshots
- [x] Migration guidance from loopback-only operation
- [x] Accepted RFC and ADRs
- [x] Release notes, packaging, and version 0.22.0

## Slice 4 security model

Remote browser authentication is admitted in three ordered stages: the resolved client
address consumes a bounded monotonic window, the bearer credential is authenticated in
constant time, and the stable operator id consumes an independent bounded window before
a durable session is issued. A blocked operator therefore receives no new cookie. Tracking
capacity is bounded and fails closed until expired windows are reclaimed.

HTTPS public origins require `Secure`, host-only, `HttpOnly`, `SameSite=Strict` cookies.
Session CSRF evidence is bound to the exact canonical public origin, including a non-default
port. Loopback HTTP remains supported only for literal loopback addresses. The dashboard
uses relative same-origin requests, so the same packaged assets operate over HTTP loopback
or HTTPS without mixed-content URLs.

Remote audit events use fixed event names and allowlisted result enums. Client addresses are
represented by keyed HMAC-SHA-256 fingerprints plus coarse family, scope, and provenance
facts. Raw client addresses, peer addresses, proxy chains, Host, Origin, and credential
headers are never copied into audit payloads or snapshots.


## Accepted runtime architecture

`RuntimeAssembler` preserves the existing loopback-only server when no explicit network policy
is supplied. An explicit fixed-port `ControlPlaneNetworkPolicy` selects
`ControlPlaneSecureHttpServer`, which owns Host and Origin validation, canonical direct or
trusted-proxy client resolution, client allowlists, per-client request and connection limits,
and either the guarded plaintext loopback listener or the native TLS listener.

Remote exposure requires durable operator mode. The Runtime constructs Secure cookie and exact
public-origin bindings, independent client/operator login throttles, protected address audit,
and native TLS before the HTTP service becomes reachable. Reverse shutdown stops HTTP and TLS
first, closes network admission state, and only then releases session and repository services.

Safe health is available through `ControlPlaneSecureHttpSnapshot`. It contains transport,
network-policy, guard, TLS certificate-health, login-throttle, and audit counters but never
certificate paths, private-key material, raw client addresses, proxy chains, Host or Origin
headers, credentials, cookie values, CSRF values, or exception text.

## Acceptance

RFC-0022 is accepted for Phoenix OS 0.22.0. Remote administration remains opt-in and
fail-closed. The absence of an explicit network policy preserves the v0.21.0 loopback HTTP
behavior, including ephemeral local ports. Explicit policies require a fixed port so the
listener, Host validation, browser origin, cookies, and CSRF evidence cannot disagree.
## Compatibility

The default policy preserves the v0.21.0 behavior:

- bind host `127.0.0.1`;
- ephemeral port permitted;
- HTTP loopback origin;
- no proxy headers;
- loopback-only client networks;
- native TLS disabled;
- non-Secure cookie policy for loopback HTTP.

Remote mode is rejected unless TLS, HTTPS origin, Secure cookies, explicit client networks, and a nonzero port are configured together.
