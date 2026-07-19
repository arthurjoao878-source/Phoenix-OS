# ADR-0039 — Reconcile before replay and retain terminal commands only

- Status: Accepted
- Date: 2026-07-19

## Context

A process can stop after a side effect succeeds but before its receipt becomes terminal. Blindly
replaying the original request would risk duplicate jobs or repeated cancellation. Journal growth
must also remain bounded without deleting commands that may still be executing.

## Decision

A Runtime-owned recovery worker probes deterministic job and workflow state for non-terminal records.
It marks a command terminal only when the external effect can be proven; otherwise it defers without
replaying payloads. Recovery passes, polling intervals, and batch sizes are bounded.

A separate Runtime-owned retention worker plans deletion by age and terminal-count limits. It deletes
only terminal records, binds every candidate to an optimistic revision, and removes the record and
idempotency index atomically. Pending and executing records are never retention candidates.

The Dashboard reads newest-first allowlisted history and never receives idempotency digests, request
fingerprints, arguments, outputs, tokens, proofs, secrets, or exception text.

## Consequences

Recovery favors safety over availability: uncertain effects remain deferred for later inspection.
Retention can reclaim bounded storage without invalidating in-flight commands. Operators receive
coarse counters and result codes rather than internal execution details.
