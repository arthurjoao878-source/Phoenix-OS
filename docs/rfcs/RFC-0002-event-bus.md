# RFC-0002 — Phoenix Event Bus

- Status: **Accepted**
- Accepted: 2026-07-17

## Summary

Phoenix requires a small observer mechanism so the Kernel and future adapters can expose
lifecycle facts without direct dependencies. The Event Bus is asynchronous, in-process,
deterministic, dependency-free, and fully awaited by the publisher.

## Goals

- Immutable event contracts with identity, time, source, payload, metadata, correlation,
  and causation.
- Exact subscriptions plus a global wildcard observer.
- Deterministic ordering by descending priority, then registration order.
- Safe registration and removal while another publish is in progress.
- One-shot subscriptions safe against nested publication.
- Failure isolation with inspectable reports and optional aggregate raising.
- Caller cancellation propagation and explicit close semantics.

## Non-goals

The Event Bus is not a remote broker, durable log, job queue, command bus, retry engine,
schema registry, transaction manager, metrics backend, or background worker.

## Public API

- `EventBus.subscribe(event_name, handler, priority=0, once=False)`
- `EventBus.unsubscribe(subscription)`
- `EventBus.publish(event, error_policy=...)`
- `EventBus.emit(name, source=..., payload=...)`
- `EventBus.close()`

## Delivery semantics

Delivery is **at most once** per matching subscription for each call to `publish`.
Handlers are invoked serially from a snapshot. This preserves reproducibility and avoids
hidden concurrency. A handler added during dispatch starts with the next event; removal
during dispatch does not alter the current snapshot. A one-shot subscription is removed
before invocation so nested publication cannot call it twice.

A synchronous handler is permitted for lightweight adapter compatibility; asynchronous
handlers are awaited. Publishers must not use handlers for unbounded work.

## Errors and cancellation

Ordinary handler exceptions are captured and subsequent handlers still run.
`ErrorPolicy.COLLECT` returns them in `DispatchReport`. `ErrorPolicy.RAISE` raises
`EventDispatchError` only after every matching handler has been attempted.
`asyncio.CancelledError` always propagates immediately.

## Security and privacy

Events must contain the minimum observable data. Secrets, raw credentials, sensitive file
contents, and unrestricted user input must not be placed in lifecycle payloads.

## Acceptance criteria

The implementation must pass tests for immutability, ordering, priorities, wildcard,
one-shot behavior, mutation during dispatch, nested publication, failure isolation,
strict errors, cancellation, close, correlation/causation, and Kernel integration.
