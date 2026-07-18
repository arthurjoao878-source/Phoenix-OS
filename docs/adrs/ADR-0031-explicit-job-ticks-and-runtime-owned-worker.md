# ADR-0031 — Explicit job ticks and a Runtime-owned bounded worker

- Status: Accepted
- Date: 2026-07-18

## Context

Embedding an invisible background loop inside the scheduler would make tests, shutdown, and failure
recovery timing-dependent. Requiring every host to reinvent a service loop would produce inconsistent
polling, batching, lease, and lifecycle behavior.

## Decision

`JobScheduler.run_due()` remains an explicit deterministic bounded tick. `JobWorker` is a separate
one-shot lifecycle adapter that repeatedly invokes ticks with configured polling, batch, worker, and
lease limits. `RuntimeAssembler` starts the worker after plugins and other services, then stops it
first during reverse shutdown. Tick infrastructure failures are reduced to safe exception categories,
counted, and isolated so the service loop can continue.

## Consequences

Unit tests can call exact ticks with explicit times, while Runtime deployments receive a standard
bounded worker. Graceful shutdown waits for the active tick and then closes the scheduler repository.
Long-running capability work must use deadlines appropriate for operational shutdown requirements.
The core still does not provide cron parsing, distributed consensus, a hosted queue, or exactly-once
external effects.
