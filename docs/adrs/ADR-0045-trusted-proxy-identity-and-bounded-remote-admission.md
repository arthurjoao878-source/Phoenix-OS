
# ADR-0045 — Trusted-proxy identity and bounded remote admission

- Status: Accepted
- Date: 2026-07-19

## Context

A remote administrative listener must not trust attacker-supplied forwarding headers, retain raw
client addresses in audit records, or permit one client or login target to consume unbounded
memory and connections.

## Decision

Direct peer addresses are canonical IP literals. Forwarded identity is accepted only when the
direct peer belongs to an explicit trusted-proxy CIDR and exactly one configured header format is
present. Untrusted or ambiguous proxy evidence fails closed.

The resolved client must belong to an explicit allowlist and consumes bounded request,
connection, and login windows. Remote login admission independently limits the protected client
identity and stable operator UUID before a session cookie is issued. Audit uses keyed
HMAC-SHA-256 address fingerprints plus coarse family, scope, provenance, and result enums; it
excludes raw addresses, proxy chains, headers, credentials, cookies, and internal exceptions.

## Consequences

Proxy topology and address allowlists become reviewed deployment configuration. Capacity
exhaustion denies new admission instead of evicting active security state. Address fingerprints
support correlation only while the deployment retains the same protection secret. Deployment
owners remain responsible for upstream proxy hardening, firewall enforcement, secret custody,
alerting, and denial-of-service capacity planning.
