# RFC-0015 — Durable Jobs and Workflow Scheduling

- Status: Draft
- Target: Phoenix OS 0.15.0
- Date: 2026-07-18

## Summary

Phoenix OS will provide a provider-neutral scheduler for one-time and recurring jobs. Jobs invoke only
registered Phoenix capabilities, never arbitrary Python imports, shell commands, or operating-system
automation. Repository leases provide atomic claims and fencing tokens so competing workers cannot
complete the same execution attempt.

## Goals

- immutable job, schedule, retry, lease, run, and snapshot contracts;
- deterministic one-time and fixed-interval scheduling;
- atomic claims with bounded leases and stale-result rejection;
- bounded retries with deterministic exponential backoff;
- explicit dead-letter state after permanent failure;
- cancellation that invalidates an active lease;
- capability-only execution through `CapabilityRegistry`;
- safe Event Bus facts without raw arguments, outputs, or exception messages;
- an in-memory reference repository for tests and ephemeral deployments;
- a durable `StateStore` repository with transactional claims and restart recovery.

## Non-goals

This RFC does not add cron parsing, a distributed consensus system, exactly-once external side effects,
arbitrary code execution, shell access, a workflow DSL, a UI, or a hosted queue service. Durable
repositories reduce duplicate execution but cannot make external effects exactly once. Capability
providers remain responsible for idempotency where retries are possible.

## Contracts

`JobSpec` identifies a registered capability, JSON-compatible arguments, a trusted
`CapabilityContext`, a `JobSchedule`, a `RetryPolicy`, and an optional execution deadline.

`JobSchedule` contains a timezone-aware first execution time and an optional positive fixed interval.
Recurring schedules advance at a fixed rate and skip missed occurrences rather than creating an
unbounded catch-up burst.

`JobStatus` contains:

- `scheduled`;
- `running`;
- `retrying`;
- `succeeded`;
- `cancelled`;
- `dead_letter`.

`JobLease` contains a job id, opaque fencing token, worker id, acquisition time, expiry, and attempt
number. Only the exact active lease may complete or fail an attempt.

## Repository semantics

A `JobRepository` must atomically:

1. add a new job id once;
2. list due jobs in deterministic order;
3. claim a due or expired job with a new fencing token;
4. reject stale or expired completion tokens;
5. persist completion, retry, cancellation, or dead-letter transitions;
6. expose complete records for diagnostics and recovery.

The in-memory implementation is process-local. `StateJobRepository` encodes the same contracts
through the existing `StateStore` boundary. Serializable transactions protect claim, completion,
failure, and cancellation transitions across repository instances sharing one store. The adapter
borrows the store lifecycle and persists a versioned JSON-safe schema for restart recovery.

## Scheduler semantics

`JobScheduler.run_due()` is an explicit deterministic tick. It lists due records, atomically claims
each record, invokes the named capability, and records the result. The scheduler does not hide a
background task. Deployment adapters may call ticks from a timer, service loop, or external trigger.

Capability authorization, confirmation, deadlines, event observation, and provider error
normalization remain owned by `CapabilityRegistry`. The scheduler stores only a safe exception class
name, not raw exception messages that may contain secrets.

## Retry and dead-letter behavior

`RetryPolicy.max_attempts` counts total execution attempts. After a failed attempt, the next run time
is calculated from a deterministic exponential delay with an optional maximum. When no attempts
remain, the record enters `dead_letter` and is no longer due.

An expired lease represents an abandoned execution. A later worker receives a new attempt and fencing
token. If the expired attempt already exhausted the retry budget, the record transitions to
`dead_letter` rather than remaining permanently stuck in `running`.

## Recurring jobs

After a successful recurring execution, attempts reset to zero and the next fixed-rate occurrence is
the first schedule time strictly after the completion tick. Failures use the retry policy before the
recurring schedule advances.

## Cancellation

Cancellation is allowed for non-terminal jobs. Cancelling a running job removes its active lease, so a
late worker result is rejected as stale. Terminal records are immutable through ordinary scheduler
operations.

## Events

The first slice emits:

- `job.scheduled`;
- `job.started`;
- `job.completed`;
- `job.retrying`;
- `job.dead_lettered`;
- `job.cancelled`.

Payloads contain only job id, capability name, status, and attempt number. Correlation and causation
come from the trusted capability context.

## Security considerations

Jobs are authority-bearing delayed requests. Hosts must construct `CapabilityContext` from trusted
identity and policy inputs. Persisted arguments may contain sensitive domain data even after ordinary
redaction, so durable adapters require access control, encryption, retention, and backup policies.

Lease fencing prevents ordinary duplicate completion but does not stop a capability provider from
performing an external side effect before its lease expires. Providers should accept idempotency keys
or otherwise tolerate at-least-once execution.

## Acceptance criteria for implemented slices

- immutable validated contracts;
- deterministic in-memory due ordering;
- atomic competing claims;
- stale and expired lease rejection;
- one-time completion;
- fixed-rate recurrence;
- retry and dead-letter transitions;
- cancellation;
- capability-only execution;
- safe failure categories;
- scheduler snapshot counters;
- versioned `StateStore` persistence and safe schema validation;
- recovery of scheduled, retrying, cancelled, and expired-lease records after restart;
- serializable competing claims across repository instances;
- strict typing, formatting, and regression tests.

## Follow-up slices

- Runtime lifecycle integration;
- Policy Engine actions for schedule, inspect, cancel, and retry;
- Audit Ledger mappings and observability metrics;
- explicit idempotency keys and manual dead-letter replay;
- bounded scheduler service loop adapters.
