# ADR-0042 — State Store-backed durable operator sessions

- Status: Accepted
- Date: 2026-07-19

## Context

RFC-0020 temporary operator sessions were intentionally process-local. Runtime restarts therefore
forced every operator to authenticate again and erased the durable evidence needed to distinguish
expiry, rotation, logout, and administrative revocation. Phoenix OS also needs session history and
bounded retention without persisting browser credentials.

## Decision

Phoenix OS stores schema-v1 durable session records through the provider-neutral State Store. Each
record contains operator bindings, absolute and idle deadlines, rotation generation and lineage,
lifecycle status, optimistic revision, and SHA-256 digests of the session token and CSRF secret.
Plaintext credentials never cross the repository boundary.

Record, token, operator, and lineage indexes are updated atomically. Canonical JSON, per-record
checksums, strict allowlisted decoding, canonical identifiers, and complete index verification make
unknown schemas or corrupted state fail closed. `RuntimeAssembler` selects the State Store adapter
when a default store exists and otherwise uses the bounded in-memory reference repository.

A Runtime-owned recovery worker reconciles expired or stale active records after restart. A separate
retention worker removes only standalone terminal records under bounded age/count policies;
rotation-lineage records remain protected while their predecessor/successor relationship exists.

## Consequences

Authenticated sessions, expiry decisions, revocations, and replay-resistant rotated predecessors
survive Runtime reconstruction. Storage grows with protected rotation lineage until a future
chain-aware compaction policy is introduced. Deployments must protect the State Store and treat
schema or index corruption as an authentication outage rather than silently rebuilding authority.
