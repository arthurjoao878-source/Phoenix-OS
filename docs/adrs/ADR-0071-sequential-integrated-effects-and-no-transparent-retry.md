# ADR-0071: Integrated effects are sequential and never transparently retried

- **Status:** Accepted
- **Date:** 2026-08-28
- **Related:** RFC-0036

## Context

Integrated orchestration coordinates multiple protected subsystems with different effect
semantics. Parallel effectful steps, hidden retry, stale approvals, or deadline and
cancellation races could duplicate external side effects or continue work after current
authority has changed.

## Decision

Phoenix v0.36.0 admits at most one effectful integrated step at a time per run.

Before effect admission Phoenix validates and normalizes the proposal, resolves exact
bindings/resources, propagates provenance, performs data-flow admission, applies
`tool.invoke`, applies downstream canonical authorization, and finally revalidates
freshness, profile generation, budget, deadline, and cancellation.

Potentially effectful integrated work is never transparently retried. A later attempt
after proven no-effect is a new proposal with a new attempt identity and fresh current
authorization.

If an authoritative downstream boundary cannot prove completion or non-execution after
an effect may have started, the attempt is `INDETERMINATE`. Automatic repetition is
blocked and durable execution enters RFC-0028 reconciliation when configured.

## Consequences

- Parallel effectful integrated execution is outside v0.36.0.
- Cancellation prevents new admission but does not promise rollback.
- Child deadlines cannot extend the remaining parent deadline.
- The most restrictive applicable authoritative limit wins.
- Prior approvals and ALLOW decisions cannot be replayed as later admission.
- Effect uncertainty remains explicit across failure and recovery.

## Alternatives considered

- **Retry effectful work automatically on timeout.** Rejected because the previous effect
  may already have occurred.
- **Run multiple protected effects concurrently.** Rejected for v0.36.0 because
  deterministic ordering and recovery semantics are intentionally sequential.
- **Assume cancellation means no effect.** Rejected because cancellation cannot revoke an
  external effect that may have started.

## Supersession criteria

A replacement must preserve deterministic pre-effect ordering, current final
revalidation, explicit effect certainty, no transparent repetition after possible effect
start, and non-amplifying budget/deadline/cancellation semantics.
