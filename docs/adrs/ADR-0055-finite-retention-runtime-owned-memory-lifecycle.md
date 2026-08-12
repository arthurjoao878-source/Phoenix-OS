# ADR-0055: Finite retention and Runtime-owned bounded memory lifecycle

- **Status:** Accepted
- **Date:** 2026-08-12
- **Related:** RFC-0030

## Context

Persistent memory can accumulate indefinitely, while semantic providers, index
rebuilds, cleanup, or recovery can hang startup/shutdown or amplify work. Deletion
without durable anti-resurrection semantics can also allow stale derived state to
reappear after restart.

## Decision

Every configured memory domain has finite per-record bytes, metadata/provenance
bounds, record count, total bytes, record TTL, tombstone retention, query/result
limits, and context limits.

Deletion creates authoritative absence with tombstone semantics sufficient to
prevent stale-index or recovery resurrection. Expired and tombstoned records are
absent from reads, retrieval, context assembly, and recovery.

Runtime owns optional memory store wrappers, derived index, recovery, cleanup, and
maintenance lifecycle. Scope/record work per cycle is finite. Provider calls and
recovery have explicit operation deadlines. Shutdown cancels maintenance and waits
only for a finite grace. If memory startup recovery fails or is cancelled, the owner
self-cleans its store/index wrapper before propagating failure because the global
Runtime cannot roll back a component whose `start()` never completed.

Operational events and administration expose only content-free IDs, counters,
statuses, and fixed reason codes.

## Consequences

- Memory cannot grow or run maintenance without configured finite ceilings.
- Process restart cannot make expired/deleted records visible through the reference
  recovery path.
- A hanging provider or cancellation-resistant worker cannot block shutdown forever.
- Safe operational surfaces can diagnose lifecycle state without disclosing memory
  content, queries, or embeddings.

## Alternatives considered

- **Unlimited retention with manual cleanup.** Rejected because persistence becomes
  unbounded by default.
- **Background workers not owned by Runtime.** Rejected because cancellation,
  rollback, and shutdown become nondeterministic.
- **Rely only on global Runtime rollback for startup failure.** Rejected because a
  component is added to Runtime's active set only after successful `start()`.

## Supersession criteria

A replacement must preserve finite storage and retention, authoritative
anti-resurrection deletion, bounded provider/recovery/cleanup/shutdown work,
startup self-cleanup, and content-free operational surfaces.
