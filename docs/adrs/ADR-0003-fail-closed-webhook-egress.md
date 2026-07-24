# ADR-0003: Fail-closed webhook egress

- **Status:** Accepted
- **Date:** 2026-07-24
- **Related RFC:** [RFC-0024](../rfcs/RFC-0024-durable-signed-webhooks-and-event-subscriptions.md)

## Context

A configurable webhook endpoint is a server-side request forgery boundary.
Validation performed only when a subscription is created is insufficient:
DNS can change, a hostname can resolve to several addresses, and ambient HTTP
clients may apply proxies, redirects, credential discovery, or permissive
response handling.

Phoenix must not let a previously valid subscription reach loopback, private,
link-local, multicast, metadata-service, or otherwise unapproved destinations
after DNS or network changes.

## Decision

Every outbound attempt uses a dedicated fail-closed transport that performs this
sequence:

1. validate the canonical endpoint and its named `WebhookEgressPolicy`;
2. resolve the hostname again for the current attempt;
3. normalize and bound every returned literal IP address;
4. require every resolved address to satisfy the allowed port and network
   policy;
5. connect directly to an admitted literal address while retaining the original
   hostname for TLS certificate verification and SNI;
6. send one bounded HTTP/1.1 POST without ambient proxy behavior;
7. reject redirects and protocol switching;
8. bound connection time, total time, request headers, response headers, header
   count, response line size, response body size, and resolved-address count;
9. retain only safe status and error classifications, not raw response bodies.

Production endpoints use HTTPS. Insecure HTTP is available only for explicit
loopback development when both the endpoint and egress policy opt into it.

The transport does not follow redirects. A 3xx response is a terminal response
unless a future ADR defines a reviewed redirect policy.

## Consequences

Positive consequences:

- DNS rebinding cannot rely on creation-time validation;
- all addresses in a multi-address answer must be admissible;
- connection pinning prevents a second uncontrolled resolution by an HTTP
  client;
- proxy environment variables and ambient credential behavior are excluded;
- receiver responses cannot consume unbounded memory;
- audit and administrative surfaces can use bounded error categories.

Costs and constraints:

- endpoints behind changing private networks require explicit reviewed CIDRs;
- mixed public and private DNS answers are rejected rather than partially used;
- redirects commonly accepted by general HTTP clients are incompatible;
- the dedicated transport carries more implementation responsibility than a
  convenience client;
- DNS and admission occur on every attempt.

## Alternatives considered

### Validate only when creating or updating a subscription

Rejected because DNS and routing facts are time-dependent and may change before
a later retry.

### Allow any address returned for an approved hostname

Rejected because one malicious or misconfigured answer would create an SSRF
path and address selection could vary.

### Use a general HTTP client with redirects disabled

Rejected because ambient proxies, connection pooling, secondary resolution,
authentication plugins, and hidden defaults are difficult to audit as one
egress boundary.

### Follow same-origin or same-host redirects

Rejected for v0.24.0 because redirects introduce another resolution and policy
decision and can change the request target after signing.

### Permit private destinations by default

Rejected because private and local network authority must be explicit in the
named egress policy.

## Supersession criteria

A replacement transport ADR must preserve per-attempt resolution, literal
destination admission and pinning, TLS hostname verification, bounded I/O, no
ambient authority, and fail-closed behavior for every address.
