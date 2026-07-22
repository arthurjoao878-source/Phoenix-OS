# ADR-0047 - Exact scoped and replay-protected machine API

- Status: Accepted
- Date: 2026-07-21

## Context

Accepting API tokens on browser or generic control-plane routes would allow
machine credentials to cross trust boundaries designed for human operators.
A valid bearer token also needs protection against replay, broad implicit
authority, transport ambiguity, and unbounded authentication attempts.

## Decision

API-token authentication is accepted only by explicitly registered machine
routes under `/v1/control-plane/machine/`. Each route declares one exact HTTP
method, path, authorization action, resource, and handler. Unknown paths and
methods do not fall through to generic execution.

Every machine request supplies exactly one bearer authorization value, one
`X-Phoenix-Request-Nonce`, and one aware
`X-Phoenix-Request-Timestamp`. Phoenix canonicalizes the method, route, query,
and request-body digest before replay validation. An optional
`X-Phoenix-Correlation-Id` is propagated only as bounded tracing context.

Authentication checks token and account state, expiration, optional client CIDR
binding, optional mutual-TLS certificate identity, replay evidence, and
independent client and account throttles. Authorization then requires both the
token's exact action and resource grants and approval from the central
deny-by-default Policy Engine.

Machine authentication does not use browser cookies, CSRF, operator sessions,
human roles, or step-up evidence. Browser-only headers are rejected at the
machine boundary. Handlers receive a credential-free request and trusted
service-account context.

Authentication failures are generic. Audit and observability retain only
allowlisted protected facts and bounded counters; they exclude tokens, token
digests, raw network identities, headers, request bodies, and internal
exceptions.

## Consequences

Adding a machine operation requires an explicit reviewed route and matching
scope and resource semantics. Possession of a token does not authorize any
route that was not registered and granted.

Clients must create a fresh nonce and current aware timestamp for every request.
Retries require new replay evidence. Deployments using network or mutual-TLS
restrictions must keep those identities synchronized with the token metadata.

Machine clients cannot substitute API tokens for Dashboard login or Maintainer
administration. Human and machine authentication remain separate fail-closed
boundaries.
