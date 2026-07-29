# ADR-0018: Bounded serial agent loop with no transparent retry

- **Status:** Accepted
- **Date:** 2026-07-29
- **Related:** RFC-0027

## Context

Agent loops can consume unbounded model turns, tokens, bytes, time, queue slots,
and tool capacity. Retrying a model turn or tool call after an ambiguous failure
can duplicate billable work or external side effects. Parallel tool execution
also complicates ordering, cancellation, approval, and partial-failure semantics.

## Decision

The initial agent Runtime is one deterministic in-memory state machine. It
executes at most one tool call per model turn and at most one tool invocation at
a time per run. Every transition is explicit and one run succeeds only through
one terminal state.

Finite limits cover steps, model turns, tool calls, prompt bytes, model-output
bytes, tool-result bytes, tokens, structured depth and width, queue depth,
concurrency, per-operation timeouts, approval wait, total duration,
cancellation grace, and shutdown grace. The most restrictive applicable limit
wins, and admission occurs before model or tool work begins.

There is no transparent retry of model turns or tool calls. After an ambiguous
external failure, Phoenix returns a safe indeterminate failure rather than
repeating the operation. A reviewed adapter may use the stable tool-call
identifier as an idempotency key, but Phoenix does not claim exactly-once
execution.

Cancellation rejects new work, signals active work, stops accepting additional
output, waits only for finite grace, releases admission capacity, invalidates
unused approvals, and records a content-free terminal category.

## Consequences

- Termination and resource usage are mechanically bounded.
- Side effects are not duplicated by hidden orchestration retries.
- Throughput within one run is intentionally lower than a parallel planner.
- Callers that retry must do so explicitly with domain-specific reconciliation.
- Restart-resumable runs require a later durable protocol and are not implied by
  this Runtime.

## Alternatives considered

- **Unlimited iterative planning.** Rejected because it has no finite safety or
  operational bound.
- **Automatic exponential retry.** Rejected because execution may already have
  reached an external system.
- **Parallel tool fan-out.** Rejected for the initial release because it expands
  partial-failure, approval, and cancellation complexity.

## Supersession criteria

A later concurrent or durable agent design may supersede this record only with
finite budgets, explicit side-effect reconciliation, no hidden duplicate work,
and deterministic terminal and cancellation semantics.
