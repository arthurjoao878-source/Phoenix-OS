# ADR-0032 — Deterministic DAGs and Job-Backed Workflow Steps

- **Status:** Accepted
- **Date:** 2026-07-18
- **RFC:** RFC-0016

## Context

Phoenix durable jobs execute one capability invocation, but multi-step work needs explicit dependency
ordering, parallel branches, recovery, and terminal propagation. Persisting callables, module paths,
pickles, or shell commands would bypass the capability security boundary and make recovery unsafe.

## Decision

Workflow definitions are immutable directed acyclic graphs of capability-backed steps. Construction
rejects duplicate identifiers, missing dependencies, self-dependencies, and cycles. Planning uses a
deterministic topological order that preserves declaration order within each parallel level.

Every runnable workflow step is represented by one durable job. Its identifier is UUIDv5 derived from
the workflow instance identifier and normalized step identifier. Recovery therefore reattaches a job
that was durably created before the workflow revision was persisted instead of dispatching a duplicate.

## Consequences

- fan-out and fan-in are deterministic and testable;
- existing capability policy, confirmation, deadlines, retries, leases, and audit remain authoritative;
- graph mutation after instance creation is not supported;
- external effects are at least once and still require provider idempotency;
- hosted queues, remote execution, and distributed consensus remain external boundaries.
