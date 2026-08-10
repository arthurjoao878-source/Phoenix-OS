# ADR-0022: Fenced leases and conditional durable mutation

- **Status:** Accepted
- **Date:** 2026-08-10
- **Related:** RFC-0028

## Context

A time-bounded lease alone cannot stop a paused, partitioned, or delayed worker from
continuing after ownership has moved to another worker. Wall-clock expiry is also
insufficient as proof of exclusive mutation authority.

Durable recovery therefore needs a store-enforced mechanism that rejects stale
workers even when old process state continues to execute.

## Decision

Phoenix OS requires one durable lease for recovery and leased run mutation. Every
lease acquisition atomically creates a strictly increasing fencing generation.
Renewal preserves the generation; reacquisition after expiry creates a newer one.

Every leased run or checkpoint mutation carries the exact expected run version,
lease identifier, and current fencing generation. Store-side conditional mutation
is authoritative. Writes from an expired, replaced, mismatched, or lower
generation fail closed.

Recovery never trusts a pre-acquisition read as current. After acquiring a fenced
lease, the coordinator re-reads the current checkpoint and validates it again
before transition or external work.

A worker that loses renewal stops admitting new model and tool work immediately.
It cannot complete, cancel, reconcile, or persist later run results with stale
fencing authority.

Fencing generations are not client-selected administration authority. Human and
machine administration use their own exact authorization boundaries, and cleanup
uses the bounded retention worker's exclusive cleanup protocol while skipping
actively leased runs.

## Consequences

- Two workers cannot both commit durable progress for the same generation.
- Delayed stale workers remain harmless at the persistence boundary.
- Recovery paths carry explicit version, lease, and generation evidence.
- Lease acquisition and mutation require atomic store support.
- Cleanup and administration cannot bypass run fencing by supplying client values.

## Alternatives considered

- **Lease expiry by wall clock only.** Rejected because a stale worker may continue
  after expiry or observe ambiguous time.
- **Process-local mutexes.** Rejected because they do not survive restart and do not
  coordinate independent workers.
- **Owner identifier without generation.** Rejected because an owner value can be
  reused while stale work remains in flight.
- **Let clients provide the fencing generation.** Rejected because fencing is
  server-owned mutation authority, not request data.

## Supersession criteria

A replacement must retain store-enforced stale-worker rejection, monotonic
ownership epochs or stronger fencing, post-acquisition re-read, optimistic version
checks, and separation between run mutation authority and administrative or
cleanup inputs.
