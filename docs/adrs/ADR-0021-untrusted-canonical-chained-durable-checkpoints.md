# ADR-0021: Untrusted canonical chained durable checkpoints

- **Status:** Accepted
- **Date:** 2026-08-10
- **Related:** RFC-0028

## Context

Restart-resumable agent execution requires persisted state, but persisted state can
be corrupted, rolled back, substituted across runs, restored from an older backup,
or influenced by model and tool content. A checkpoint must therefore reconstruct
reviewed state without becoming a continuation token or carrying stale authority.

## Decision

Phoenix OS treats every durable checkpoint as untrusted data. A checkpoint grants
no policy decision, approval, credential, lease, tool registration, model
selection, or proof that external work succeeded.

Checkpoint envelopes are immutable, versioned, bounded, canonical Phoenix-owned
records. The strict codec rejects duplicate keys, malformed Unicode, non-finite
numbers, unsupported structures or versions, oversized values, and non-canonical
encodings.

Every accepted checkpoint is bound to one stable durable run, one strictly
increasing sequence, the expected previous checkpoint digest, the durable run
version, and a canonical envelope digest. Store mutations use optimistic versions
and reject sequence reuse, conflicting records, cross-run substitution, and stale
updates.

Recovery validates run identity, schema version, sequence continuity, previous
digest linkage, canonical digest, run version, terminal consistency, payload
reference consistency, retention state, and tombstone state before reconstructing
anything. Current configuration, registry, schemas, limits, policy, and approved
compatibility rules always override persisted metadata.

The checkpoint chain detects rollback within the active store history. It does not
replace storage access control, trusted backups, audit, or external signatures.

## Consequences

- Restart recovery has a deterministic fail-closed persistence boundary.
- A valid old checkpoint cannot silently restore old authority.
- Storage and codecs require explicit versioning and migration discipline.
- Restored backups can still require explicit administrative freshness review.
- Models and tools cannot migrate durable state or choose checkpoint authority.

## Alternatives considered

- **Serialize the Python continuation.** Rejected because stacks, coroutine frames,
  provider objects, callbacks, sockets, and executable state are not reviewed
  durable contracts.
- **Trust any checkpoint with a valid digest.** Rejected because integrity alone
  does not establish freshness, authorization, compatibility, or external outcome.
- **Persist previous policy and approval decisions as authority.** Rejected because
  restart must use current security decisions.
- **Accept best-effort decoding of old schemas.** Rejected because ambiguous durable
  state can widen recovery behavior.

## Supersession criteria

A replacement must preserve checkpoint-as-data semantics, strict bounded canonical
decoding, exact run and sequence binding, rollback/substitution detection,
optimistic mutation, current-security precedence, and fail-closed version
migration.
