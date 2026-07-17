# ADR-0012 — Structured signals and deterministic sinks

- **Status:** Accepted
- **Date:** 2026-07-17

Phoenix observability uses immutable structured log, metric, and completed-span records. An
in-process hub exports them serially in explicit priority and registration order. Exporters are
ordinary synchronous or asynchronous sink adapters. The core does not create background workers,
batches, retries, persistence, or vendor protocols. Sink failures are collected by default and may
be raised only after every sink has been attempted; cancellation always propagates.
