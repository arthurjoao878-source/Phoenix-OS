# ADR-0033 — Runtime-Owned Workflow Reconciliation and Safe Events

- **Status:** Accepted
- **Date:** 2026-07-18
- **RFC:** RFC-0016

## Context

Durable workflow state must advance after job completion and process restart. A hidden global loop
would weaken deterministic lifecycle ownership, make shutdown ordering unclear, and complicate tests.
Workflow observability must not disclose step arguments, outputs, credentials, or provider details.

## Decision

`WorkflowWorker` is a one-shot Runtime lifecycle component with bounded polling and explicit
snapshots. Runtime starts the job worker before the workflow worker and stops them in reverse order,
so workflow reconciliation stops before the scheduler closes.

`WorkflowOrchestrator` emits only stable `workflow.*` facts containing workflow identifiers, names,
versions, status, revision, step identifiers, and step status. Definitions, arguments, outputs, and
errors are not copied into event payloads. `SecurityJournal` maps these facts to
`AuditCategory.WORKFLOW`.

## Consequences

- startup, background reconciliation, shutdown, and failure counters are explicit;
- direct orchestrator calls remain deterministic and testable without the worker;
- audit records can trace graph transitions without storing job inputs or outputs;
- reconciliation failures are isolated and surfaced through worker snapshots;
- repositories and schedulers retain separate ownership boundaries.
