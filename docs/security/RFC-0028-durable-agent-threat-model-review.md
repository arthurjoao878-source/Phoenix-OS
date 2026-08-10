# RFC-0028 durable-agent threat-model and security-invariant review

- **Reviewed:** 2026-08-10
- **Release:** Phoenix OS v0.28.0
- **Scope:** durable RFC-0028 checkpoints, storage, leases, fencing, recovery,
  authorization, approvals, attempts, reconciliation, protected payloads,
  retention, cleanup, administration, observability, Runtime composition,
  migration, and compatibility
- **Result:** Accepted for the v0.28.0 durable-agent release gate

## Review method

This review maps the RFC-0028 threat model and all forty-five security
invariants to implementation boundaries and executable regression suites. It
treats checkpoints, persisted metadata, decrypted protected content, model and
tool content, approval state, lease records, timestamps, recovery requests,
storage failures, adapter responses, and reconciliation evidence as untrusted
until the relevant Phoenix-owned boundary validates them.

A passing test does not prove that an installed storage, model, tool, secret,
or reconciliation adapter is benign. Installed adapters remain trusted
deployment code and must be reviewed for their own filesystem, database,
network, secret, operating-system, and external-system authority.

The review uses five evidence classes:

1. immutable contracts, canonical codecs, bounded stores, and checkpoint-chain
   validation;
2. fresh authorization, approval revalidation, compatibility checks, leases,
   fencing, and optimistic mutation;
3. durable attempt identity, safe-boundary recovery, explicit indeterminate
   reconciliation, cancellation, and no-transparent-retry behavior;
4. explicit protected-content configuration, authenticated protection,
   retention, tombstones, safe administration, and content-free observation;
5. opt-in Runtime composition, migration/rollback guidance, compatibility, and
   the full project quality gate.

## Trust boundaries

### Untrusted

- checkpoint bytes, persisted envelopes, metadata fields, payload references,
  restored backups, storage errors, and records returned by a durable store;
- protected payload plaintext after decryption and all model or tool content
  reconstructed from it;
- model responses, tool results, provider metadata, external status responses,
  and reconciliation evidence;
- identifiers, timestamps, approval state, lease records, and recovery requests
  until bound to the current run and validated;
- any persisted policy, approval, configuration, registry, schema, model,
  provider, resource, or limit information when used to decide current
  authority.

### Trusted but least-authority

- reviewed Phoenix configuration and Runtime composition;
- Phoenix-owned checkpoint codecs, compatibility rules, resource resolvers,
  policy decisions, approval gates, lease/fencing implementation, and retention
  policy;
- installed storage, model, tool, secret, and reconciliation adapters;
- trusted operator and service-account security contexts;
- versioned protection-key resolution through trusted secret composition.

Trusted adapters receive only the validated data and dependencies required for
their reviewed operation. RFC-0028 is not a hostile-code sandbox.

## Threat review

| Threat | Required control | Evidence |
| --- | --- | --- |
| Corrupted, truncated, oversized, malformed, or unsupported checkpoint | Strict canonical bounded codec; immutable schema version; full digest validation; fail closed | `test_agent_durable_codec.py`, `test_agent_durable_contracts.py`, `test_agent_durable_recovery.py` |
| Rollback, sequence reuse, or cross-run checkpoint substitution | Monotonic sequence, previous-digest chain, run binding, optimistic version, history validation | `test_agent_durable_memory.py`, `test_agent_durable_sqlite.py`, `test_agent_durable_recovery.py` |
| Persisted state reused as execution authority | Checkpoint is data only; fresh exact resume, model, and tool authorization; current policy wins | `test_agent_durable_authorization.py`, `test_agent_durable_recovery.py` |
| Approval replay or expired approval restored after restart | Current exact approval revalidation; invocation binding; expiry and consumption remain authoritative | `test_agent_durable_approval.py`, `test_agent_durable_authorization.py` |
| Stale configuration, schema, registry, model, provider, or resource | Current compatibility assessment overrides persisted metadata and pauses or fails closed on material change | `test_agent_durable_compatibility.py`, `test_agent_durable_recovery.py` |
| Concurrent recovery or stale worker mutation | One active lease, monotonic fencing generation, store-side conditional mutation, post-acquisition re-read | `test_agent_durable_lease.py`, `test_agent_durable_races.py`, `test_agent_durable_memory.py`, `test_agent_durable_sqlite.py` |
| Process loss after model or tool submission | Stable attempt identity; prepared/start boundaries; active attempt becomes indeterminate unless exact outcome is proven | `test_agent_durable_attempts.py`, `test_agent_durable_indeterminate_recovery.py` |
| Duplicate external side effects after restart | No transparent retry; safe-boundary recovery only; exactly-once is not claimed | `test_agent_durable_no_transparent_retry.py`, `test_agent_durable_recovery.py` |
| Forged or unsafe reconciliation | Exact run/attempt/version binding, current authorization, reviewed evidence, fenced mutation, one-time preparation | `test_agent_durable_reconciliation.py`, `test_agent_durable_reconciliation_administration.py` |
| Protected payload disclosure or plaintext fallback | Metadata-only default; explicit protected-content opt-in; authenticated protection; strict bounds; no plaintext fallback | `test_agent_durable_protected_payload.py`, `test_agent_durable_observer.py` |
| Key rotation, wrong key version, or authentication failure | Versioned configured keys; authorization and lease before decryption; missing/revoked/invalid keys fail closed | `test_agent_durable_protected_payload.py` |
| Retention or cleanup deletes active work | Server-owned bounded retention; actively leased runs skipped; finite worker passes | `test_agent_durable_retention_memory.py`, `test_agent_durable_retention_worker.py`, `test_agent_durable_cleanup_administration.py` |
| Terminal run resurrected after cleanup | Terminal tombstones retain anti-resurrection identity until reviewed expiry | `test_agent_durable_retention_memory.py`, `test_agent_durable_sqlite.py` |
| Cancellation or shutdown admits new external work | Cancellation stops new model/tool work; workers and leases drain or expire within finite bounds; reverse lifecycle close | `test_agent_durable_cancellation_shutdown.py`, `test_agent_durable_worker.py`, `test_agent_durable_runtime_composition.py` |
| Audit, health, administration, logs, metrics, or events leak content | Content-free projections, fixed Phoenix-owned event types, safe categories, authorization before existence disclosure | `test_agent_durable_observer.py`, `test_agent_durable_administration.py` |
| Machine or destructive administration gains broad authority | Machine administration default-off; exact scopes/resources; destructive operations require exact actions, confirmation, step-up, and audit | `test_agent_durable_administration.py`, `test_agent_durable_reconciliation_administration.py`, `test_agent_durable_cleanup_administration.py` |
| Tool-result or recovered-content injection gains authority | Recovered model/tool content remains untrusted and re-enters RFC-0027/RFC-0026 validation and authorization boundaries | `test_agent_durable_recovery.py`, `test_agent_durable_authorization.py` |
| Upgrade silently changes v0.27.0 behavior | Durable composition is optional; omitted configuration creates no durable store, worker, run, payload, lease, event, or administration service | `test_agent_durable_runtime_composition.py`, `test_durable_agent_migration_guidance.py` |

## Security-invariant review

### Invariants 1–6: opt-in durability, stable identity, and checkpoint-as-data

**Result: satisfied.** Durable execution is disabled unless explicitly
configured and enabling the capability creates no run or new authority by
itself. Durable runs and checkpoints use stable Phoenix-owned identities,
immutable schema versions, monotonic sequences, and checkpoints never grant
execution or policy authority.

Evidence includes `test_agent_durable_contracts.py`,
`test_agent_durable_memory.py`, `test_agent_durable_sqlite.py`, and
`test_agent_durable_runtime_composition.py`.

### Invariants 7–14: fresh authority, current compatibility, and approvals

**Result: satisfied.** Persisted decisions are informational only. Resume,
every resumed model turn, and every resumed tool call require current
authorization. Current configuration, registry, schemas, limits, policy, and
approval state override persisted metadata. Removed or materially changed
dependencies fail closed, and approval evidence remains exact and current.

Evidence includes `test_agent_durable_authorization.py`,
`test_agent_durable_approval.py`, `test_agent_durable_compatibility.py`, and
`test_agent_durable_recovery.py`.

### Invariants 15–21: leases, fencing, atomic mutation, and strict history

**Result: satisfied.** One run has at most one active lease holder. Every
acquisition advances a monotonic fencing generation, and store-side mutation
requires the current lease/generation and expected version. Stale workers
cannot mutate. State transitions and checkpoints are atomic, sequence gaps are
not silently accepted, and malformed or unsupported checkpoints fail closed.

Evidence includes `test_agent_durable_lease.py`,
`test_agent_durable_races.py`, `test_agent_durable_memory.py`,
`test_agent_durable_sqlite.py`, and `test_agent_durable_codec.py`.

### Invariants 22–28: attempts, indeterminate work, no retry, and reconciliation

**Result: satisfied.** Recovery resumes only from reviewed safe boundaries and
does not repeat completed work. An active external attempt at process loss is
indeterminate unless a reviewed protocol proves its exact outcome.
Indeterminate work is never retried automatically, Phoenix does not claim
exactly-once side effects, and reconciliation cannot rewrite the original
invocation identity.

Evidence includes `test_agent_durable_attempts.py`,
`test_agent_durable_indeterminate_recovery.py`,
`test_agent_durable_no_transparent_retry.py`,
`test_agent_durable_recovery.py`, and
`test_agent_durable_reconciliation.py`.

### Invariants 29–34: protected content and fail-closed decryption

**Result: satisfied.** Durable persistence is metadata-only by default.
Protected continuation content is explicit opt-in, authenticated, bounded,
versioned, and finitely retained. Encryption does not replace authorization.
Plaintext and ciphertext are excluded from safe operational surfaces, key or
authentication failure never falls back to plaintext, and payload references
remain inside their configured namespace.

Evidence includes `test_agent_durable_protected_payload.py`,
`test_agent_durable_observer.py`, and
`test_agent_durable_administration.py`.

### Invariants 35–37: retention, active-lease safety, and anti-resurrection

**Result: satisfied.** Retention and cleanup are finite, actively leased runs
are not cleanup candidates, protected content is removed under the reviewed
protocol, and terminal tombstones prevent stale state from recreating a
deleted terminal run.

Evidence includes `test_agent_durable_retention_memory.py`,
`test_agent_durable_retention_worker.py`,
`test_agent_durable_cleanup_administration.py`, and
`test_agent_durable_sqlite.py`.

### Invariants 38–40: cancellation, shutdown, and bounded workers

**Result: satisfied.** Cancellation prevents new model/tool work. Shutdown and
worker lifecycle are bounded, durable admission closes before destructive
dependencies, and recovery/reconciliation/retention/cleanup queues,
concurrency, attempts, and duration remain finite.

Evidence includes `test_agent_durable_cancellation_shutdown.py`,
`test_agent_durable_worker.py`, and
`test_agent_durable_runtime_composition.py`.

### Invariants 41–44: safe observation, failures, recovered results, and recursion

**Result: satisfied.** Durable events and operational views are content-free,
public failures omit protected or execution content and raw exceptions,
recovered tool results remain untrusted, and durable recovery cannot recursively
create another durable recovery path or autonomous goal.

Evidence includes `test_agent_durable_observer.py`,
`test_agent_durable_administration.py`,
`test_agent_durable_recovery.py`, and
`test_agent_durable_runtime_composition.py`.

### Invariant 45: v0.27.0 compatibility

**Result: satisfied.** With durable-agent configuration absent, Phoenix OS
retains v0.27.0 behavior. Upgrade does not create durable runs, checkpoints,
payloads, leases, workers, permissions, approvals, model calls, tool calls, or
external access. Disabling durability stops new durable admission and automatic
recovery without disabling ordinary RFC-0027 in-memory agent execution or
RFC-0026 inference.

Evidence includes `test_agent_durable_runtime_composition.py` and
`test_durable_agent_migration_guidance.py`.

## Residual risks

- A malicious or defective installed storage, model, tool, secret, or
  reconciliation adapter can abuse authority explicitly granted to that adapter.
  Code review, process isolation, operating-system controls, and external-system
  permissions remain deployment responsibilities.
- The checkpoint digest chain detects rollback and substitution within the
  validated active store history; it does not replace trusted storage access
  control, protected backups, external signatures, or independent audit.
- An external system may commit a model or tool side effect before Phoenix can
  durably record the result. The run can remain indeterminate until reviewed
  evidence resolves it; exactly-once execution is not promised.
- Idempotency keys reduce duplicate risk but are only as strong as the external
  system's implementation and do not prove an outcome by themselves.
- Destroyed, unavailable, or incorrectly rotated protection keys can make
  retained protected payloads permanently unrecoverable. Phoenix must fail
  closed rather than weaken protection.
- Stable identifiers, counts, ages, sizes, durations, and approved digests are
  content-free but may still reveal operational traffic patterns. Sink access
  and retention remain deployment concerns.
- Restoring an old database or backup can reintroduce old records. Recovery must
  revalidate current policy, configuration, history, leases, retention, and
  compatibility before any work continues.
- Future checkpoint schemas, protection algorithms, distributed recovery,
  autonomous scheduling, or new machine administration require separate review
  rather than inheriting this acceptance automatically.

## Release conclusion

The RFC-0028 threat-model and security-invariant review is accepted for the
Phoenix OS v0.28.0 durable-agent release gate.

This document does not by itself accept RFC-0028 or authorize publication.
Final release acceptance still requires the full project quality gate, the
named durable-agent release gate, wheel and sdist inspection, isolated offline
installation and execution, final release metadata, artifacts, and checksums
against the release commit.
