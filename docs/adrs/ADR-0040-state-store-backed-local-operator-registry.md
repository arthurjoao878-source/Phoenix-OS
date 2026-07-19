# ADR-0040 — State Store-backed local operator registry

- Status: Accepted
- Date: 2026-07-19

## Context

The loopback control plane previously authenticated one anonymous administrator bearer. Phoenix OS
needs stable operator identities and role-specific authorization without persisting plaintext
credentials or coupling the feature to one database provider.

## Decision

Phoenix OS stores versioned local operator records through the provider-neutral State Store. Each
record contains identity metadata, a built-in role, explicit additive permissions, lifecycle state,
optimistic revision, token version, and a SHA-256 credential digest only. Independent username and
token-digest indexes are updated atomically with the record. Canonical JSON and record checksums
provide fail-closed corruption detection.

`RuntimeAssembler` selects the default State Store when available and otherwise creates a bounded
in-memory registry. A configured bootstrap maintainer is added only when its normalized username is
absent; subsequent starts reuse the persisted identity instead of replacing its credential.

## Consequences

Operator identity and credential rotation survive Runtime reconstruction while plaintext bearer
material remains outside storage. Deployments must retain the bootstrap credential securely and use
explicit rotation rather than changing startup configuration silently. Unknown schemas, broken
indexes, duplicate identities, and checksum mismatches prevent authentication.
