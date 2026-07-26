# ADR-0008: Shared Control Plane listener and exact inbound routes

- **Status:** Accepted
- **Date:** 2026-07-25
- **Related RFC:** [RFC-0025](../rfcs/RFC-0025-secure-inbound-event-gateway-and-external-event-sources.md)

## Context

A separate inbound HTTP server would duplicate TLS, mTLS, proxy, CIDR, Host,
request parsing, rate limiting, connection limiting, audit, observability, and
shutdown logic. Two listeners could drift in configuration and expose different
network authority even though both belong to the Control Plane security
perimeter.

A single wildcard ingress endpoint would also require source discovery after
reading untrusted input and could accidentally keep disabled or revoked sources
reachable.

## Decision

Inbound event ingress reuses the existing Control Plane listener. It creates no
second socket and inherits the listener's reviewed loopback or remote exposure,
native TLS or mTLS, public origin, Host validation, trusted proxy policy, client
CIDR admission, per-client connection limits, request timeouts, and audit and
shutdown behavior.

Each active durable source owns one exact route derived from its canonical name:

```text
/v1/control-plane/inbound/<source-name>
```

Routes are registered only after Runtime startup validates durable sources and
schemas. Source lifecycle mutations update the route registry only after the
durable repository mutation succeeds:

- creating a source adds no route because new sources begin disabled;
- enabling a source adds its exact route;
- renaming an active source replaces the old exact route;
- disabling or revoking a source removes its route.

Unknown, disabled, revoked, stale, and partially updated routes fail closed with
no-store responses. There is no wildcard source route and no caller-selected
source identifier in the body.

The listener asks the ingress adapter synchronously whether it handles the path
and what body limit applies before reading the request body. The per-source body
bound therefore remains effective at the transport boundary. Strict request
line, header count, header bytes, body bytes, JSON structure, concurrency,
request rate, and global admission limits remain finite.

Inbound HMAC and service-account submission share the same HTTP transport but
retain separate credential validation. When a service-account source is used,
the secure listener supplies the trusted RFC-0023 transport context; a caller
cannot manufacture it through headers.

## Consequences

Positive consequences:

- Phoenix has one network exposure and TLS authority for the Control Plane;
- ingress receives the same proxy, CIDR, Host, timeout, and connection controls;
- source disable and revoke remove reachability instead of only rejecting later;
- body limits are selected before untrusted body allocation;
- exact routes avoid source enumeration through a generic endpoint;
- Runtime shutdown removes ingress before repositories and workers close.

Costs and constraints:

- inbound events require an existing Control Plane listener;
- remote external producers must satisfy the complete RFC-0022 network policy;
- route names are part of the producer contract and renames are operational
  changes;
- source activation changes the shared listener's route table;
- listener request limits must accommodate both browser administration and
  bounded inbound bodies without weakening either boundary.

## Alternatives considered

### Create a dedicated inbound listener

Rejected because it duplicates security-sensitive network code and creates a
second exposure lifecycle.

### Use one wildcard `/inbound` endpoint

Rejected because Phoenix would need to discover the source from untrusted
headers or bodies and could retain reachability for inactive sources.

### Register routes for disabled sources and reject inside the gateway

Rejected because disabled authority should be absent at the earliest routing
boundary.

### Read the maximum possible body before selecting a source

Rejected because one global maximum would bypass narrower per-source limits and
consume unnecessary memory.

### Trust forwarded client headers directly

Rejected because proxy identity is accepted only through the existing explicit
trusted-proxy policy.

## Supersession criteria

A future ADR may introduce another listener or routing model only if it provides
one equally reviewed network authority, exact inactive-source removal,
pre-allocation body bounds, trusted transport context, finite admission, and
deterministic startup and shutdown ownership.
