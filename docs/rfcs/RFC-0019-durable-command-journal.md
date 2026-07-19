# RFC-0019 — Durable Command Journal and Recovery

- Status: Accepted
- Target release: Phoenix OS v0.19.0
- Authors: Phoenix contributors
- Created: 2026-07-19

## Summary

RFC-0019 makes the administrative command boundary introduced by RFC-0018 durable. Commands will
retain payload-free identity, idempotency, lifecycle, result receipts, and recovery state through a
provider-neutral repository backed by the Phoenix State Store. The Dashboard will gain a paginated
operation history without exposing arguments, outputs, tokens, proofs, secrets, or exception text.

## Motivation

RFC-0018 intentionally uses a bounded process-local idempotency store. A process restart therefore
forgets completed receipts and may leave an operator unable to distinguish a command that never ran
from one whose side effect completed before the response was returned. A durable command journal is
needed before operational commands can provide restart-safe idempotency and recovery.

## Safety invariants

- journal records contain no command payload, job arguments, workflow definitions, outputs, tokens,
  CSRF values, confirmation proofs, plaintext idempotency keys, secrets, or exception messages;
- each record is bound to a command UUID, action, target, authenticated principal, SHA-256
  idempotency digest, and request fingerprint;
- schemas are explicitly versioned and unknown versions fail closed;
- repository updates use optimistic revisions;
- lifecycle transitions are deterministic and terminal records cannot be replaced;
- history pagination has fixed bounds and deterministic ordering;
- durable recovery reconciles side effects before retrying execution;
- retention never deletes pending or executing commands;
- corruption and incompatible persisted data are reported through generic typed errors.

## Command lifecycle

```text
pending -> executing -> succeeded
                    -> rejected
                    -> failed
pending -----------> succeeded
        -----------> rejected
        -----------> failed
```

Direct pending-to-terminal transitions support recovery when a side effect can be proven to have
completed before the journal recorded `executing`. Terminal records are immutable.

## Slice plan

### Slice 1 — Contracts and in-memory reference repository

Completed in this branch:

- immutable, schema-versioned `ControlPlaneCommandJournalRecord`;
- `pending`, `executing`, `succeeded`, `rejected`, and `failed` states;
- payload-free construction from `ControlPlaneCommandIntent`;
- bounded page contracts and non-sensitive snapshots;
- repository protocol;
- bounded in-memory reference repository;
- deterministic newest-first pagination;
- unique command and idempotency-digest indexes;
- optimistic revisions and validated lifecycle transitions;
- typed duplicate, not-found, conflict, capacity, and closed errors.

### Slice 2 — State Store persistence and corruption detection

Completed in this branch:

- `StateControlPlaneCommandJournalRepository` backed by the provider-neutral `StateStore`;
- atomic record and idempotency-index creation through serializable transactions;
- canonical schema-v1 JSON bytes and SHA-256 record digests;
- strict allowlisted decoding with exact envelope, record, and index fields;
- optimistic State Store versions for lifecycle transitions;
- restart recovery of records, terminal receipts, revisions, and indexes;
- durable digest lookup without retaining plaintext idempotency keys;
- detection of checksum mismatch, missing links, mismatched indexes, duplicate identities, malformed
  fields, key/record disagreement, and unsupported schemas;
- typed persistence, corruption, and schema errors;
- borrowed State Store lifecycle so repository shutdown does not erase durable history.

### Slice 3 — Durable idempotency and interrupted-command recovery

Completed in this branch:

- `JournalControlPlaneIdempotencyStore` backed by the durable journal repository;
- restart-safe reservation, replay, completion, failure, and explicit rejection receipts;
- pending-to-executing journal transitions before command side effects;
- race-safe replay using durable idempotency digests and request fingerprints;
- borrowed repository lifecycle so command API shutdown does not erase history;
- payload-free job and workflow side-effect probes;
- deterministic recovery of created jobs, dead-letter retries, job cancellation, and workflow cancellation;
- safe deferred outcomes when external state cannot prove completion;
- bounded `ControlPlaneCommandRecoveryService` reconciliation passes;
- lifecycle-compatible `ControlPlaneCommandRecoveryWorker` with bounded ticks and safe counters;
- generic failure isolation without persisted payloads or exception text.

### Slice 4 — History API, retention, and audit integration

Completed in this branch:

- authenticated `GET /v1/control-plane/commands/history` pagination;
- allowlisted `ControlPlaneCommandHistoryView` and page serializers;
- omission of idempotency digests, request fingerprints, payloads, outputs, and exception text;
- deterministic terminal-only retention planning by age and retained count;
- bounded scans and deletion batches with optimistic revision binding;
- atomic record and idempotency-index deletion in memory and State Store repositories;
- conflict and failure counters without command identities or storage details;
- safe `control-plane.command.journal.*` Event Bus facts consumed by the Security Journal;
- command-journal counters in `ControlPlaneSnapshot` and health degradation when the source is closed.

### Slice 5 — Dashboard and v0.19.0 release integration

Completed in this branch:

- Dashboard operation-history table with status, action, target, time, principal, and safe result code;
- journal counters in the dashboard overview;
- `RuntimeAssembler` selection of State Store-backed or bounded in-memory repositories;
- Runtime-owned journal closure, recovery worker, retention worker, history service, and HTTP integration;
- periodic bounded terminal retention with safe operational counters;
- public service discovery for journal, history, recovery, and retention components;
- accepted RFC, ADR-0038/0039, migration guidance, release notes, packaging, and v0.19.0 version update.

## Non-goals

RFC-0019 does not persist request bodies, add arbitrary command replay, expose internal exceptions,
provide remote administration, add multi-user identity, or weaken RFC-0018 authorization, CSRF,
confirmation, origin, capability-risk, and loopback boundaries.

## Acceptance

RFC-0019 is accepted for Phoenix OS 0.19.0. The implementation keeps command payloads outside the
journal, preserves restart-safe idempotency through State Store records, reconciles interrupted side
effects without blind replay, and exposes only bounded allowlisted history through the loopback
control plane.
