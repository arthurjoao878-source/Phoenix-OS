# ADR-0036 — Separate allowlisted command boundary

- Status: Accepted
- Date: 2026-07-19

## Context

The read-only dashboard introduced in RFC-0017 cannot perform routine local operations. Adding generic
write methods to the existing read API would blur authorization, serialization, idempotency, and audit
boundaries and could accidentally expose internal schedulers or repositories.

## Decision

Phoenix OS adds a separate command API with four fixed actions: job creation, job cancellation,
dead-letter retry, and workflow cancellation. Each action maps to one exact permission. Immutable
command contracts validate canonical payloads before handler execution, and every request requires an
opaque idempotency key whose plaintext is never retained.

Handlers receive narrow scheduler, orchestrator, and capability-catalog protocols. They derive trusted
execution context from the authenticated principal and never accept caller-provided security context,
metadata, providers, callables, outputs, leases, or repository records. Command UUIDs become created
job UUIDs so partial success and replay can reconcile without duplicate scheduling.

Command receipts use explicit serializers and contain only action, target, command ID, lifecycle
status, timestamps, stable result code, and an optional created job ID.

## Consequences

The dashboard can perform common local operations without becoming a generic administration or code
execution surface. New mutations require a new action, permission, immutable contract, handler,
serializer, transport route, audit fact, and tests rather than automatically inheriting access to
internal service methods.
