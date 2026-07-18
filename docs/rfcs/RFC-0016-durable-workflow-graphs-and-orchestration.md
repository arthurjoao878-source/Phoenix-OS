# RFC-0016 — Durable Workflow Graphs and Orchestration

- **Status:** Accepted
- **Target:** Phoenix OS 0.16.0
- **Depends on:** RFC-0003, RFC-0004, RFC-0007, RFC-0009, RFC-0012, RFC-0015

## Summary

Phoenix OS needs a provider-neutral orchestration layer for multi-step durable work. RFC-0015
established durable capability-backed jobs, leases, retries, recovery, and Runtime-owned workers.
RFC-0016 composes those jobs into validated directed acyclic graphs without adding arbitrary code,
operating-system commands, or a distributed broker to the core.

A workflow definition declares immutable capability-backed steps and explicit dependencies. The core
validates uniqueness, missing dependencies, self-dependencies, and cycles before an instance is
created. A deterministic topological plan groups independent steps into fan-out levels and preserves
fan-in barriers for dependent steps.

## Goals

- immutable workflow definitions and step contracts;
- deterministic directed-acyclic-graph validation and planning;
- explicit fan-out and fan-in dependencies;
- durable workflow instance and step state;
- optimistic persistence and restart recovery;
- one durable job per runnable step;
- capability-mediated execution with existing policy and confirmation boundaries;
- deterministic success, failure, retry, cancellation, and dependency propagation;
- Runtime, Event Bus, Audit Ledger, and observability integration.

## Non-goals

- arbitrary Python callables or serialized executable objects;
- shell commands or operating-system automation in the core;
- BPMN interpretation, visual workflow editing, or a UI;
- cross-region consensus or a built-in distributed broker;
- universal exactly-once external side effects;
- unbounded dynamic graph mutation after an instance starts.

## Initial contracts

`WorkflowStep` identifies one capability, immutable arguments, trusted capability context, retry
policy, deadline, metadata, and a set of dependency step identifiers. `WorkflowDefinition` owns an
ordered tuple of steps and rejects malformed graphs during construction.

`WorkflowPlanner` produces deterministic topological levels. Declaration order is preserved inside
each level, so the same definition always produces the same plan. Root steps begin `ready`; all other
steps begin `blocked`.

`WorkflowRecord` stores immutable instance state with an optimistic revision. The reference
`InMemoryWorkflowRepository` provides process-local atomic replacement and conflict detection.
`StateWorkflowRepository` persists the same immutable records through the generic `StateStore`
boundary using a versioned JSON-safe schema. Exact workflow revisions and underlying State Store
versions are both checked during replacement, so stale writers fail closed. Reopening a repository
over the same store recovers definitions, step state, capability context, retry policy, outputs, and
terminal metadata without importing a database vendor into the workflow subsystem.


`WorkflowOrchestrator` assigns a deterministic UUIDv5 job identifier to every workflow-step pair.
This makes dispatch restart-safe: if a process stops after the durable job is created but before the
workflow revision is replaced, recovery attaches the same job instead of creating a duplicate. The
orchestrator reconciles terminal job state, releases dependency barriers in declaration order, and
uses the existing job retry and lease model without bypassing the `CapabilityRegistry`. A failed step
terminates the workflow and cancels every outstanding sibling or descendant job. Explicit or external
cancellation propagates to all remaining steps.

## Safety model

Workflow graphs select only registered Phoenix capabilities. They do not bypass capability policy,
confirmation, deadlines, redaction, events, or audit. Persisted definitions must remain JSON-safe;
secrets belong behind `SecretRef` values and trusted capability providers.

A workflow can coordinate execution but cannot make an external side effect exactly once. Providers
must use idempotency keys or transactional integration when duplicate external effects are unsafe.

## Planned implementation slices

1. immutable graph contracts, cycle validation, deterministic planning, and in-memory repository;
2. State Store persistence, versioned encoding, optimistic recovery, and corruption detection
   (implemented);
3. job-backed orchestrator, dependency release, fan-out/fan-in, failure and cancellation propagation
   (implemented);
4. Runtime worker, Event Bus, Audit Ledger, public API, documentation, examples, and v0.16.0 release
   (implemented).


## Runtime and audit integration

`WorkflowWorker` performs bounded reconciliation ticks under Runtime lifecycle ownership. Runtime
starts the job worker before the workflow worker and stops the workflow worker first, preserving
access to job state during final reconciliation and cancellation. Direct `advance()` and `recover()`
operations remain available for deterministic tests and deployments that own their own service loop.

The orchestrator emits redacted `workflow.*` facts containing stable identifiers and lifecycle
status only. Step arguments, outputs, capability context, and provider errors are not included in the
event payload. `SecurityJournal` categorizes these records as `AuditCategory.WORKFLOW`.

## Acceptance

RFC-0016 is accepted for Phoenix OS 0.16.0 with deterministic immutable DAGs, durable optimistic
persistence, job-backed execution, restart-safe dispatch, Runtime reconciliation, safe events, and
audit integration. Dynamic graphs, compensation engines, remote workers, and distributed consensus
remain outside this RFC.
