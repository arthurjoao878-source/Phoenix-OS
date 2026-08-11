# ADR-0049: Monotonic root budget reservation across delegation

- **Status:** Accepted
- **Date:** 2026-08-11
- **Related:** RFC-0029

## Context

Delegation can multiply work. If completed children return their reserved allowance
to a root, or if restart forgets historical reservations, a parent can serially
create more model turns, tool calls, bytes, tokens, duration, or children than the
root was ever allowed to consume.

Concurrency release and authority/budget release are therefore different concepts.

## Decision

Every admitted child receives a finite reservation derived from the remaining
trusted root allowance. Root model turns, tool calls, input/output tokens,
prompt/result bytes, duration, total-child count, and per-parent fan-out are
monotonic lifetime accounting dimensions.

Completing, failing, cancelling, or expiring a child releases concurrency capacity
but does not restore its historical reservation. Durable coordination persists the
content-free reservation and counts terminal records after restart. New durable
records are admitted only if the same atomic transaction can prove that root budget,
total children, and per-parent fan-out remain within the current configured limits.

An indeterminate sibling blocks new or resumed work for the same root until reviewed
reconciliation resolves the unknown execution state. Phoenix never guesses that an
unknown reservation or external attempt is safe to reuse.

## Consequences

- Delegation cannot increase the root run's total configured budget.
- Serial completion cannot be used to multiply lifetime allowance.
- Restart does not reset delegation capacity.
- Operators may need explicit reconciliation before additional work can proceed
  after an ambiguous process loss.

## Alternatives considered

- **Return all child budget on completion.** Rejected because it enables unbounded
  serial amplification.
- **Track only concurrent children.** Rejected because concurrency is not lifetime
  budget.
- **Reconstruct accounting only from live in-memory state.** Rejected because restart
  would restore spent capacity.

## Supersession criteria

A replacement must prove that total delegated work cannot exceed the trusted root
allowance across completion, cancellation, failure, restart, and concurrent
admission.
