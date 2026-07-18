# Phoenix OS v0.16.0 — Durable Workflow Graphs and Orchestration

Phoenix OS 0.16.0 implements RFC-0016 and builds durable multi-step orchestration on top of the
capability-only job scheduler introduced in 0.15.0.

## Highlights

- immutable workflow definitions and execution records;
- deterministic directed-acyclic-graph validation and cycle rejection;
- declaration-ordered topological planning;
- parallel fan-out and dependency-safe fan-in;
- in-memory and State Store-backed workflow repositories;
- optimistic revisions and recovery after process restart;
- one deterministic UUIDv5 durable job per workflow step;
- capability-mediated execution with existing policy, confirmation, deadline, and retry boundaries;
- failure and cancellation propagation across siblings and descendants;
- Runtime-owned `WorkflowWorker` reconciliation;
- safe `workflow.*` Event Bus facts and `AuditCategory.WORKFLOW` journal records;
- public API, executable example, RFC, ADRs, migration guidance, and regression tests.

## Safety model

Workflow graphs contain stable capability names and JSON-safe inputs, not Python callables, pickles,
shell commands, or executable objects. Persisted records do not include secret material by design;
providers should resolve secrets behind reviewed references and preserve idempotency for external
side effects.

Stable workflow-step job identifiers make dispatch restart-safe when the process stops between job
creation and workflow revision persistence. The scheduler still provides at-least-once execution,
so exactly-once external effects remain a provider or integration responsibility.

## Validation

- Ruff checks passed;
- Ruff formatting passed;
- mypy strict passed;
- 550 tests passed;
- durable workflow example completed successfully;
- package and plugin compatibility version updated to 0.16.0.

## Current boundaries

The core does not include dynamic graph mutation, BPMN, cron calendars, visual editing, a hosted
queue, cross-region consensus, remote executors, universal compensation, or exactly-once external
side effects. These remain external adapters or future RFCs.
