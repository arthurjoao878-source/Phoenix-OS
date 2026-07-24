# ADR-0004: Bounded webhook retry and redrive

- **Status:** Accepted
- **Date:** 2026-07-24
- **Related RFC:** [RFC-0024](../rfcs/RFC-0024-durable-signed-webhooks-and-event-subscriptions.md)

## Context

Webhook delivery is an at-least-once integration. Networks fail, receivers
throttle, processes stop during attempts, and operators sometimes need to retry
a corrected dead-letter delivery.

Unbounded retries can create permanent load, surprise external side effects,
and hide receiver failures. Resetting attempt history during manual redrive
would bypass safety limits and destroy forensic continuity.

## Decision

Each delivery has one immutable ordered attempt history and one global bounded
attempt budget. The subscription retry policy may be narrower, but it cannot
exceed the Phoenix global maximum.

The dispatcher:

- claims due work with optimistic revision checks;
- rechecks that the subscription is active before every attempt;
- records one completed attempt with a safe outcome classification;
- schedules deterministic bounded backoff only for retryable failures with
  remaining budget;
- transitions exhausted retryable work to dead letter;
- treats terminal failures as terminal without automatic retry.

Runtime startup recovers interrupted `IN_FLIGHT` deliveries in bounded batches.
Recovery records the interrupted attempt as a safe `runtime_recovery` failure,
then either schedules the next bounded retry, moves the delivery to dead letter,
or cancels it when the subscription is missing, disabled, or revoked.

Explicit redrive:

- requires the exact `webhook.delivery.redrive` permission;
- accepts only an eligible dead-letter delivery;
- rechecks the current subscription state;
- schedules another attempt only when global budget remains;
- preserves delivery ID, canonical body, payload digest, source identity,
  signing-key version, and every prior attempt;
- never resets counters or rewrites history.

Receivers deduplicate by delivery identifier because a retry is the same
business delivery.

## Consequences

Positive consequences:

- retries are operationally finite and predictable;
- manual actions cannot evade the global safety bound;
- attempt history remains useful for audit and diagnosis;
- restart recovery has deterministic outcomes;
- inactive subscriptions stop future attempts;
- receiver deduplication has one stable identifier.

Costs and constraints:

- a corrected receiver cannot redrive a delivery whose global budget is
  exhausted;
- operators may need a new business event for another delivery after exhaustion;
- at-least-once delivery still requires idempotent receivers;
- recovery classifies an interrupted attempt as consumed work rather than
  pretending it never started.

## Alternatives considered

### Retry forever

Rejected because it creates unbounded cost and traffic and prevents a clear
terminal state.

### Reset attempts during manual redrive

Rejected because it defeats the global bound and erases security-relevant
history.

### Create a new delivery identifier for redrive

Rejected because receivers could interpret the retry as a distinct business
event and because immutable history would fragment.

### Return interrupted work directly to pending

Rejected because the receiver may already have observed the request before the
process stopped. Consuming and recording the attempt preserves at-least-once
semantics.

### Retry terminal errors after a fixed delay

Rejected because retryability is an explicit safe classification, not an
operator-independent assumption about every failure.

## Supersession criteria

A future ADR may change retry classification or scheduling but must retain a
global finite budget, immutable attempt history, stable delivery identity,
subscription-state rechecks, and explicit authorization for manual redrive.
