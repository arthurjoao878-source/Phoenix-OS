# Phoenix OS v0.15.0 — Durable Jobs and Workflow Scheduling

Phoenix OS v0.15.0 implements RFC-0015 and adds provider-neutral durable scheduling without adding
arbitrary code execution, shell access, or a hosted queue to the core.

## Highlights

- Immutable job, schedule, retry, lease, run, repository, worker, and snapshot contracts.
- Deterministic one-time and fixed-interval scheduling through explicit bounded ticks.
- Capability-only execution through `CapabilityRegistry`, including its policy, confirmation, and
  deadline boundaries.
- Atomic competing claims with opaque fencing tokens and stale-result rejection.
- Bounded exponential retries, recurring-at-fixed-rate behavior, cancellation, and dead-letter state.
- Process-local `InMemoryJobRepository` for tests and ephemeral services.
- Durable `StateJobRepository` with versioned JSON-safe encoding, serializable transitions, restart
  recovery, and expired-lease reclamation.
- Runtime-owned `JobWorker` with explicit poll, batch, worker, and lease limits.
- Safe Event Bus facts and dedicated Audit Ledger job categorization without arguments, outputs, or
  exception messages.
- RuntimeAssembler service exposure and lifecycle ordering after plugins, with reverse-order shutdown.
- RFC-0015, ADR-0030, ADR-0031, executable example, migration guidance, and regression tests.

## Delivery model

Repository fencing protects job state from stale workers. It does not make external side effects
exactly once. Providers should use idempotency keys or tolerate duplicates when retries, process
termination, lease expiry, or network ambiguity are possible.

## Compatibility

Version 0.15.0 is additive. Existing RFC-0001 through RFC-0014 contracts remain compatible. Hosts
that do not configure a job scheduler or Runtime worker retain their previous lifecycle behavior.
