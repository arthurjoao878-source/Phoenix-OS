# ADR-0058: Authoritative workspace records with a confined backing boundary

- **Status:** Accepted
- **Date:** 2026-08-14
- **Related:** RFC-0031

## Context

Workspace bytes may live behind a filesystem or another storage adapter while
Phoenix-owned metadata determines identity, scope, logical path, version, digest,
provenance, retention, deletion, and quota state. If a backing location or stale byte
object becomes record truth, substituted, expired, deleted, or wrong-version data can
reappear without the authoritative policy and lifecycle checks.

Writes also need one atomic admission decision for artifact count, total bytes,
logical-path uniqueness, identity history, and optimistic version state. A partially
published backing object must not become an authoritative artifact.

## Decision

The workspace store is authoritative for artifact existence, exact scope,
`ArtifactId`, canonical logical path, logical version, content digest, bounded
metadata and provenance, retention state, tombstones, identity anti-reuse, and quota
accounting.

A `WorkspaceBackingAdapter` is a provider-neutral byte-persistence boundary behind an
opaque Phoenix-owned key. It does not choose workspace identity, scope, logical path,
policy, retention, or quota. Reads and recovery validate authoritative metadata and
the expected canonical content digest against the backing object before disclosure.

Mutations use optimistic logical versions and atomic authoritative admission. A
successful write publishes one complete immutable backing version before the
authoritative record becomes visible. Failed or cancelled writes do not become
visible as committed artifacts, and concurrent quota or canonical-path races have at
most one authoritative winner.

Deletion and expiry make artifacts absent from reads, listings, context assembly,
transfer continuation, and recovery. Artifact identities are retained sufficiently
to prevent reuse from resurrecting deleted data. Recovery validates current
authoritative state and live backing; missing, substituted, corrupt, wrong-scope,
wrong-version, digest-mismatched, or otherwise inconsistent state fails closed.

## Consequences

- Storage adapters can be replaced without transferring workspace authority to the
  provider.
- Quota and optimistic-version correctness lives at the authoritative store boundary,
  not in best-effort adapter behavior.
- Backing corruption or substitution reduces availability but cannot silently widen
  disclosure.
- Deleted and expired artifacts cannot be resurrected merely because stale backing
  bytes survive.
- Recovery can report bounded content-free counters while still validating live
  authoritative state.

## Alternatives considered

- **Treat the filesystem or object store as the source of truth.** Rejected because
  physical byte presence would then control scope, deletion, retention, and identity.
- **Let adapters enforce quota independently.** Rejected because concurrent writers
  need one authoritative atomic admission decision.
- **Expose a write before backing publication is complete.** Rejected because readers
  could observe partial or non-durable authoritative state.
- **Reuse an `ArtifactId` after deletion.** Rejected because stale backing or transfer
  references could resurrect old data under a trusted identity.

## Supersession criteria

A replacement must preserve one authoritative Phoenix record boundary, opaque
provider-neutral backing, exact digest revalidation, atomic quota/version admission,
no partial authoritative writes, fail-closed recovery, and anti-resurrection
deletion/expiry semantics.
