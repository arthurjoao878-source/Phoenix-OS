# ADR-0034 — Loopback-only allowlisted control plane

- Status: Accepted
- Date: 2026-07-18

## Context

Phoenix OS needs an operator view of Runtime, jobs, workflows, plugins, capabilities, and audit health.
Serializing internal objects directly would expose executable providers, capability contexts,
arguments, outputs, metadata, exception messages, credentials, or cryptographic state. A network
listener would also create a new administrative attack surface.

## Decision

Phoenix OS provides a read-only control plane with explicit immutable view contracts and explicit
serializers. The built-in HTTP transport:

- accepts only literal IPv4 or IPv6 loopback addresses;
- authenticates one administrator bearer through a retained SHA-256 digest and constant-time compare;
- requires `control-plane.read` before invoking operational readers;
- supports only GET and fixed routes;
- bounds headers, bodies, response sizes, connection concurrency, and request time;
- returns generic errors without exception details;
- sets `Cache-Control: no-store` and defensive browser headers.

Operational serializers use field allowlists. They do not recursively serialize service containers,
registries, repositories, definitions, arguments, outputs, metadata, providers, audit records,
digests, Event Bus payloads, or secrets.

## Consequences

The built-in server is appropriate for local administration and testing. Remote exposure requires an
external reviewed ingress and identity boundary. New control-plane fields require an explicit
contract and serializer change rather than becoming visible automatically.
