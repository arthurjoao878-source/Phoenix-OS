# ADR-0051: Runtime-owned bounded child lifecycle and fail-closed recovery

- **Status:** Accepted
- **Date:** 2026-08-11
- **Related:** RFC-0029

## Context

Delegated children may queue, run concurrently, be cancelled with their parent,
survive a process restart as durable metadata, or be left with an unknown execution
outcome. Detached children, unbounded queues, or automatic replay of unknown running
work can outlive the root and duplicate side effects.

## Decision

Coordination is explicit opt-in Runtime composition. Runtime ownership covers the
coordinator, queue, child cancellation tokens, observer, administration boundary,
and, when configured, the durable store and recovery coordinator.

Depth, fan-out, total children, concurrency, queue depth, deadlines, child duration,
input/result size, aggregation size, and shutdown grace are finite. Parent
cancellation stops new child admission and propagates to owned queued/running
children. RFC-0029 v1 has no detached children.

Durable startup classifies pre-run `REQUESTED`, `AUTHORIZED`, and `ADMITTED` records
as recoverable. A persisted `RUNNING` child becomes `INDETERMINATE` after process
loss and is never replayed automatically. Evidence-backed reconciliation may prove
that work never started and return the same child identity to recoverable state, or
may confirm a terminal outcome. Unknown state remains indeterminate.

Recoverable replay requires an optimistic compare-and-swap claim so concurrent
owners cannot both reacquire one `DelegationId`. Current registry compatibility and
current policy are revalidated before admission.

## Consequences

- Child work cannot silently detach from its root in v1.
- Shutdown remains finite and deterministic.
- Unknown running work favors duplicate prevention over automatic availability.
- Durable coordination remains optional and does not change v0.28 behavior when
  omitted.

## Alternatives considered

- **Automatically retry every running child after restart.** Rejected because the
  child may already have executed.
- **Allow detached background children.** Rejected for v1 because ownership,
  cancellation, retention, and budget semantics would require a separate design.
- **Let multiple recoverers race and rely on child idempotency.** Rejected because
  Phoenix can enforce exclusive recovery ownership directly.

## Supersession criteria

A replacement must preserve finite lifecycle ownership, cancellation propagation,
no detached children without a new reviewed model, exclusive recovery claims,
current-state revalidation, and no transparent replay of indeterminate work.
