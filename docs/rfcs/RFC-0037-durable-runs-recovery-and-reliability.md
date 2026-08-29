# RFC-0037: Durable Runs, Recovery, and Reliability Hardening

- Status: Draft
- Target release: Phoenix OS v0.37.0
- Owners: Phoenix OS maintainers
- Architecture freeze: 2026-08-29
- Depends on: RFC-0004, RFC-0005, RFC-0006, RFC-0007, RFC-0009, RFC-0012,
  RFC-0013, RFC-0021, RFC-0026, RFC-0027, RFC-0028, RFC-0033, and RFC-0036

## Summary

RFC-0037 hardens the existing Phoenix durable-agent and integrated-agent recovery
path against process crashes, ambiguous persistence outcomes, concurrent recovery,
stale ownership, policy/configuration drift, deadline and budget discontinuities,
retention races, and crash/restart sequences that are difficult to exercise through
ordinary functional tests.

This RFC does **not** create a second durable-run engine, a second durable state
machine, a second checkpoint format, or a second authority model.

RFC-0028 remains the authoritative durable-run primitive. RFC-0036 continues to
compose that primitive for integrated execution. RFC-0037 tightens their executable
reliability guarantees, introduces deterministic failure-injection seams for tests,
and requires adversarial evidence at every important crash boundary.

The dominant rules are:

> **Recovery is continuation under fresh evidence, never replay by assumption.**

> **A restart cannot increase authority, budget, lifetime, or certainty.**

> **Unknown durable commit outcome is resolved by re-read and exact comparison,
> never blind repetition.**

> **Fencing generation, not worker belief, decides mutation ownership.**

> **An external effect with uncertain completion remains indeterminate until
> reviewed evidence proves a safe disposition.**

## Motivation

Phoenix OS v0.36.0 already has the security architecture needed for durable and
integrated agent execution.

RFC-0028 defines canonical chained checkpoints, fenced leases, current
authorization during recovery, explicit indeterminate attempts, bounded retention,
deadline and budget preservation, and safe reconciliation.

RFC-0036 reuses RFC-0028 as the sole durable-run primitive for integrated execution
and explicitly rejects a second checkpoint or durable-run engine.

The remaining reliability risk is therefore not missing architecture. It is the
difference between an architecture that is correct in ordinary execution and one
that has executable evidence under hostile timing.

Examples include:

- process loss between durable write submission and local acknowledgement;
- a checkpoint write that commits but reports an I/O failure;
- two workers racing to recover the same run;
- a stale worker continuing after lease expiry or takeover;
- restart while an external model or tool attempt is active;
- recovery after policy, profile, tool, schema, model, or resource binding changed;
- wall-clock discontinuity around lease and deadline checks;
- repeated crash/restart cycles near budget exhaustion;
- retention cleanup racing with recovery or terminalization;
- restored storage containing a stale active run after a newer tombstone existed;
- failure during recovery itself after some state has already been durably changed.

RFC-0037 converts these cases into a deterministic reliability matrix and requires
the implementation to fail closed whenever exact recovery safety cannot be proven.

## Relationship to RFC-0028 and RFC-0036

RFC-0037 is a hardening RFC.

It MUST reuse, rather than replace:

- `DurableAgentRunId`;
- `DurableRunStatus`;
- `CheckpointEnvelope`;
- `CheckpointSequence`;
- `CheckpointDigest`;
- `ExecutionAttemptId`;
- `ExecutionAttemptStatus`;
- `DurableLease`;
- `FencingGeneration`;
- `DurableRunStore`;
- `DurableLeaseManager`;
- `DurableRecoveryCoordinator`;
- `DurableAgentRuntime`;
- RFC-0028 reconciliation semantics;
- RFC-0028 retention and tombstone semantics;
- RFC-0036 integrated-task identity and durable projection;
- RFC-0033 effective-authority non-amplification.

The RFC MAY add narrowly scoped reliability-only contracts, internal classifications,
test seams, and administration diagnostics when the existing contracts cannot
express the required evidence.

It MUST NOT duplicate the RFC-0028 state machine.

It MUST NOT create a generic workflow engine.

It MUST NOT make an integrated checkpoint authoritative for downstream execution.

## Goals

- Deterministic crash and failure injection at reviewed persistence/recovery boundaries
- Exact classification of confirmed, rejected, and unknown durable mutation outcomes
- Strong checkpoint integrity evidence under truncation, corruption, substitution, and rollback
- Recovery that resolves ambiguous writes by re-reading current durable state
- Fenced takeover that rejects every stale-worker mutation path
- Deterministic concurrent-recoverer race tests
- No automatic replay of active or indeterminate external effects
- Exact reconciliation before any later fresh attempt when prior acceptance is uncertain
- Fresh current authority after every process restart
- Current profile, tool, model, schema, resource, and configuration revalidation
- Monotonic remaining budget across restart
- Original total deadline preservation across restart
- Cancellation continuity across crash/restart
- Retention and tombstone anti-resurrection hardening
- Safe restore-generation handling for stale backups
- Bounded recovery loops and bounded repeated-failure handling
- Content-free reliability diagnostics
- Network-free adversarial reliability tests
- Crash matrices covering in-memory and SQLite durable stores where applicable
- Full compatibility when durable execution is disabled or omitted
- No regression to RFC-0028 or RFC-0036 authority semantics
- Release-gate evidence specific to v0.37.0 reliability guarantees

## Non-goals

- A new durable-run state machine
- A new checkpoint serialization format unless an explicit migration is separately reviewed
- Distributed consensus
- Multi-primary durable mutation
- Exactly-once external effects
- Transparent retry of model inference
- Transparent retry of tool invocation
- Automatic reconciliation based on model claims
- Treating idempotency keys as proof of exactly-once execution
- Treating a successful local write call as sufficient durability proof
- Treating an exception from a write call as proof that nothing committed
- Extending lease duration after restart to compensate for downtime
- Resetting budgets or deadlines after restart
- Persisting new raw prompt, response, argument, result, browser, network, memory,
  workspace, clipboard, credential, secret, or approval content
- A new authorization action that bypasses `agent.resume`, `agent.reconcile`,
  `model.infer`, `tool.invoke`, or downstream protected actions
- New host, filesystem, network, browser, model, or tool authority
- Connector ecosystems or unrelated product surfaces
- Replacing SQLite transaction semantics with an application-level imitation
- General-purpose chaos infrastructure outside the durable/integrated reliability surface

## Terminology

- **Crash boundary:** a reviewed point before, during, or after a durable or external
  operation where abrupt process loss is intentionally simulated.
- **Fault point:** a stable Phoenix-owned identifier used by deterministic tests to
  inject one specific failure.
- **Mutation outcome:** the coordinator's classification of a durable mutation as
  confirmed committed, confirmed rejected/not committed, or commit outcome unknown.
- **Unknown commit outcome:** local execution cannot prove whether a durable store
  mutation committed.
- **Recovery epoch:** one bounded coordinator attempt to recover a durable run under
  one acquired fenced lease.
- **Stale worker:** a worker whose lease or fencing generation is no longer current.
- **Takeover:** acquisition of a newer fencing generation after prior ownership is
  no longer valid.
- **Live revalidation:** current-policy and current-dependency validation performed
  after restart instead of trusting persisted compatibility state.
- **Budget continuity:** preservation of already-consumed and remaining finite
  budgets across recovery.
- **Deadline continuity:** preservation of the original finite total deadline across
  recovery.
- **Restore generation:** bounded store freshness metadata used to detect a restored
  state that may predate a previously observed generation or tombstone.
- **Reliability matrix:** deterministic adversarial tests spanning crash boundaries,
  stores, recovery dispositions, and security invariants.

## Threat and failure model

RFC-0037 treats timing and partial failure as adversarial inputs.

The implementation must address:

- process termination before a durable mutation;
- process termination after store commit but before local acknowledgement;
- exceptions after a successful store commit;
- exceptions before a store commit;
- torn or truncated checkpoint bytes;
- canonical envelope corruption;
- checkpoint-digest mismatch;
- previous-digest mismatch;
- sequence gaps and duplicate sequence reuse;
- cross-run checkpoint substitution;
- rollback to an older otherwise-valid checkpoint;
- unsupported checkpoint schema;
- payload-reference mismatch;
- store version conflict;
- lease acquisition races;
- lease renewal loss;
- stale-worker writes after takeover;
- stale completion, cancellation, reconciliation, or cleanup after takeover;
- concurrent recovery workers observing the same candidate;
- process loss after attempt `PREPARED`;
- process loss after attempt `STARTED`;
- process loss after external acceptance but before local terminal recording;
- provider/tool status lookup ambiguity;
- repeated crashes during reconciliation;
- policy changes during downtime;
- removed or materially changed tools;
- changed effect classification;
- changed integrated profile generation;
- changed model/provider compatibility;
- changed resource resolver identity;
- stricter limits after restart;
- deadline expiry while the process is down;
- cancellation requested while a process is down;
- repeated restart near step/call/token/byte/duration exhaustion;
- clock rollback or discontinuity;
- retention expiry while a run is recovering;
- cleanup racing with lease acquisition;
- tombstone cleanup racing with stale state;
- stale backup restoration;
- protected-payload key unavailability after restart;
- recovery candidate enumeration failure;
- worker queue saturation;
- bounded retry exhaustion;
- observer or audit sink failure;
- shutdown during recovery;
- recovery crash after acquiring a lease;
- recovery crash after a conditional transition;
- recovery crash after reconciliation state was durably recorded.

Installed Phoenix storage, policy, model, tool, and integrated adapters remain trusted
code. Their responses, persisted bytes, clocks supplied from outside the reviewed
clock boundary, external systems, and all model/tool content remain untrusted.

## Security and reliability invariants

1. RFC-0028 remains the sole durable-agent state machine.
2. RFC-0037 creates no authority by itself.
3. A checkpoint remains untrusted data and grants no authority.
4. Restart never reuses a prior authorization as current authority.
5. Restart never restores an expired, consumed, revoked, or mismatched approval.
6. Restart never increases the configured or remaining execution budget.
7. Restart never creates a later total deadline for an existing run.
8. Downtime counts against a finite total deadline unless an existing RFC explicitly
   defines a stricter rule.
9. Every resumed protected operation receives the same fresh canonical authorization
   required without a restart.
10. Current configuration and current dependency identity win over persisted metadata.
11. An unknown durable mutation outcome is never blindly repeated.
12. Unknown durable mutation outcome is resolved by exact re-read, version comparison,
    sequence comparison, digest comparison, and transition validation.
13. A successful re-read must prove the intended exact mutation before it is treated
    as committed.
14. Absence of the intended exact mutation permits a new mutation attempt only when
    current version/fencing preconditions still hold.
15. Every recovery mutation requires the current lease identifier and fencing generation.
16. New lease acquisition creates a strictly newer fencing generation as defined by RFC-0028.
17. Every stale-worker mutation path fails closed after takeover.
18. A stale worker cannot complete, cancel, reconcile, clean up, or overwrite a newer run.
19. Lease-owner belief is never sufficient evidence of ownership.
20. Store-side conditional mutation and fencing remain authoritative.
21. Two concurrent recoverers cannot both transition one run as current owners.
22. Process loss after an external attempt reached `STARTED` never causes automatic replay.
23. Missing terminal evidence never proves that an external effect failed.
24. An indeterminate external attempt remains indeterminate until reviewed evidence
    proves a permitted disposition.
25. A later fresh attempt is permitted only after evidence establishes that the prior
    operation was not accepted or after an explicitly reviewed safe disposition.
26. Idempotency keys reduce duplicate risk but are not exactly-once proof.
27. Checkpoint corruption, truncation, substitution, rollback, unsupported versions,
    and non-canonical encoding fail closed.
28. Checkpoint chains never silently skip a sequence.
29. Restore ambiguity cannot resurrect a known terminal run automatically.
30. Tombstone anti-resurrection metadata wins over stale active records when freshness
    can be established.
31. When store freshness cannot be established, automatic recovery pauses and requires
    explicit administration rather than guessing.
32. Deadline expiry during downtime prevents new model or tool work after restart.
33. Cancellation known before recovery prevents new model or tool work.
34. Budget accounting is monotonic across every successful checkpoint transition.
35. Failed or unknown checkpoint writes cannot duplicate budget credit.
36. Recovery attempts themselves are finite and bounded.
37. Repeated crash/restart cannot create an infinite automatic recovery loop.
38. Retention cannot delete an actively and validly leased run.
39. Cleanup with stale fencing cannot delete or mutate current state.
40. Protected content remains opt-in and protected exactly as required by RFC-0028.
41. Reliability diagnostics remain content-free by default.
42. Fault injection is disabled outside explicit deterministic test composition.
43. A model, tool, checkpoint, or external response cannot select a fault point.
44. Production configuration cannot accidentally enable test-only crash injection.
45. Omission of durable configuration preserves existing non-durable behavior.
46. Omission of integrated execution preserves existing non-integrated behavior.
47. RFC-0037 changes reliability evidence, not RFC-0028/RFC-0036 authority semantics.
48. Every release gate for this RFC executes without requiring external network access.

## Deterministic fault injection

RFC-0037 introduces one narrow internal reliability-test seam.

The implementation should expose a Phoenix-owned protocol similar to:

```text
ReliabilityFaultInjector
```

with one no-op production implementation and one deterministic test implementation.

Fault injection MUST be:

- explicitly composed by tests;
- absent from ordinary RuntimeAssembler production composition;
- identified only by fixed Phoenix-owned fault-point identifiers;
- unable to receive prompt, tool argument, model output, or arbitrary user content;
- unable to grant permissions or mutate policy;
- unable to choose a different durable transition;
- deterministic from the test's configured fault plan;
- bounded so a test cannot accidentally create an unbounded failure loop.

The exact public/private module placement is an implementation decision, but the seam
must not become a model-facing tool, external API, policy action, or configurable
production feature.

Initial fault-point families should include:

```text
checkpoint.before_encode
checkpoint.after_encode
checkpoint.before_store_mutation
checkpoint.after_store_commit_before_ack
checkpoint.after_ack
lease.before_acquire
lease.after_acquire
lease.before_renew
lease.after_renew
recovery.after_candidate_read
recovery.after_lease_acquire
recovery.after_reread
recovery.after_live_revalidation
recovery.before_transition
recovery.after_transition_commit
attempt.after_prepared
attempt.after_started
attempt.after_external_return_before_terminal_record
reconcile.before_mutation
reconcile.after_mutation_commit
retention.before_delete
retention.after_delete_commit
shutdown.after_admission_stop
```

Not every store or adapter must expose every low-level hook. A fault point exists only
where Phoenix owns the corresponding boundary.

## Durable mutation outcome classification

Storage adapters already provide conditional durable operations. RFC-0037 requires
the recovery/runtime layer to explicitly distinguish three categories:

```text
CONFIRMED_COMMITTED
CONFIRMED_NOT_COMMITTED
COMMIT_OUTCOME_UNKNOWN
```

These are internal reliability classifications, not new durable-run states.

`CONFIRMED_COMMITTED` means the exact intended mutation is proven durable.

`CONFIRMED_NOT_COMMITTED` means the adapter can prove the mutation did not commit and
the prior authoritative state remains current.

`COMMIT_OUTCOME_UNKNOWN` means local execution cannot prove either case.

An unknown outcome MUST NOT trigger immediate replay.

The coordinator must:

1. stop issuing dependent durable mutations;
2. re-read the current run under valid ownership where required;
3. compare exact run version;
4. compare exact checkpoint sequence;
5. compare exact canonical digest;
6. compare exact durable status/transition;
7. compare attempt or reconciliation identity where relevant;
8. classify the mutation as already committed, not committed, or conflicting;
9. continue only from the resulting authoritative durable state.

A conflicting newer state fails the original mutation path closed.

## Checkpoint integrity hardening

RFC-0028 already requires canonical chained checkpoints.

RFC-0037 requires adversarial evidence for that design.

Tests must cover:

- one-byte corruption in canonical metadata;
- truncated canonical bytes at multiple cut positions;
- extra trailing bytes when the codec forbids them;
- duplicate JSON/object keys where applicable;
- unsupported schema version;
- wrong run identifier;
- wrong checkpoint identifier binding;
- wrong sequence;
- duplicate sequence;
- skipped sequence;
- wrong previous digest;
- wrong canonical digest;
- rollback to a previous valid checkpoint;
- cross-run substitution of a valid checkpoint;
- payload reference swapped between runs;
- terminal checkpoint followed by stale active data;
- unknown store write outcome followed by exact re-read.

The implementation must not repair malformed persisted bytes heuristically.

A malformed checkpoint cannot be passed to a model for interpretation or migration.

## SQLite durability expectations

The existing SQLite durable adapter remains the reference persistent implementation.

RFC-0037 does not invent its own transaction system.

Where SQLite is used, tests must verify Phoenix behavior around:

- atomic transaction boundaries already owned by the adapter;
- conditional run version updates;
- checkpoint and state-transition atomicity required by RFC-0028;
- lease/fencing conditional mutation;
- process reopening after a committed transaction;
- process reopening after an injected failure before commit;
- process reopening after an injected failure after commit but before local acknowledgement;
- database busy/locked handling within finite bounds;
- corruption or unreadable durable state failing closed;
- no automatic destructive repair.

The RFC does not require unsafe process-kill simulation inside SQLite internals. Tests
must inject at Phoenix-owned boundaries and may use subprocess-based crash fixtures
where exact process-loss behavior is necessary.

## Lease fencing and takeover hardening

RFC-0028 fencing remains authoritative.

RFC-0037 requires an executable stale-worker matrix.

At minimum, tests must prove that after worker B acquires a newer fencing generation,
worker A cannot:

- append a checkpoint;
- transition durable state;
- record attempt completion;
- record indeterminate status;
- reconcile an attempt;
- cancel the run;
- mark the run terminal;
- renew the obsolete lease;
- perform retention cleanup;
- remove protected payload state;
- emit an administration mutation that changes durable state.

A worker that loses renewal must stop starting new model or tool work immediately.

If local work cannot be stopped and external completion becomes unknown, the later
authoritative recovery path treats that work conservatively according to RFC-0028
indeterminate semantics.

## Concurrent recovery

The recovery candidate list is advisory.

Reading the same candidate on two workers must not imply that both may recover it.

The required sequence remains:

```text
candidate read
-> fenced lease acquisition
-> authoritative re-read
-> live validation
-> conditional recovery transition
```

Tests must run at least two deterministic recoverers against one run and force
interleavings at every Phoenix-owned step in that sequence.

Only one current fencing generation may mutate.

The loser may observe a conflict, lease rejection, newer state, terminal state, or
other safe no-op category. It may not continue based on its earlier candidate read.

## Recovery after external attempts

The RFC-0028 attempt lifecycle remains:

```text
PREPARED
STARTED
SUCCEEDED | FAILED | CANCELLED | TIMED_OUT
```

RFC-0037 adds adversarial crash evidence around those records.

A crash:

- before `PREPARED` means no durable external attempt has started;
- after `PREPARED` but before external submission may permit a fresh attempt only
  when current exact state proves that submission never began;
- after `STARTED` is indeterminate without reviewed completion evidence;
- after external return but before terminal durable recording remains indeterminate
  unless exact evidence reconstructs a safe terminal disposition.

The coordinator must never infer "not executed" from a missing terminal record.

## Indeterminate effect reconciliation hardening

Indeterminate model and tool states remain RFC-0028 states.

RFC-0037 requires failure-injection coverage for:

- crash before reconciliation authorization;
- crash after authorization but before mutation;
- crash after reconciliation commit but before acknowledgement;
- stale worker attempting reconciliation after takeover;
- duplicate reconciliation request;
- conflicting reconciliation evidence;
- evidence for the wrong attempt identity;
- evidence for the wrong external request identity;
- adapter status lookup returning unknown;
- adapter status lookup timing out;
- operator selecting `CONFIRM_NOT_STARTED` without sufficient evidence;
- a later fresh attempt only after the prior exact operation is proven not accepted.

Reconciliation remains separately authorized and immutable.

## Live revalidation after restart

A checkpoint compatibility digest is not permission to continue.

Every recovery epoch must use current server-owned dependencies.

The coordinator must revalidate the applicable current identities before new protected work,
including as relevant:

- durable checkpoint schema and migrator support;
- configured agent identity;
- integrated execution profile generation;
- tool registry descriptor identity;
- tool effect classification;
- input/output schema identity;
- resource resolver identity;
- model provider/model compatibility;
- payload profile;
- protection key availability;
- current limit profile;
- current policy;
- current approval state;
- current downstream profile generation for integrated bridges;
- current effective-authority constraints.

A material incompatibility pauses or fails recovery closed according to the existing RFC.

Persisted hashes are correlation evidence. They do not override current configuration.

## Policy and authority freshness

Recovery requires fresh `agent.resume` authorization as defined by RFC-0028.

Reconciliation requires fresh `agent.reconcile` authorization.

The next model turn requires fresh `model.infer` authorization.

The next tool invocation requires fresh `tool.invoke` authorization.

Integrated downstream bridges continue to require their existing final protected
operation authorization.

A restart cannot inherit an allow decision from:

- task admission;
- run admission;
- a prior model turn;
- a prior tool call;
- a prior downstream bridge;
- a prior checkpoint;
- a prior recovery epoch.

Tests must mutate policy between process instances and prove the new decision wins.

## Deadline continuity

Existing total deadlines remain authoritative.

The original total deadline is never replaced with `now + original_duration`.

Recovery must calculate remaining time from the original durable deadline using the
reviewed trusted clock abstraction.

If the deadline expired while Phoenix was down:

- recovery may read and classify state;
- recovery may perform the minimum safe terminalization/reconciliation bookkeeping;
- recovery cannot start new model or tool work.

Clock rollback or ambiguity must not extend authority to execute.

Tests must cover restart:

- well before deadline;
- immediately before deadline;
- exactly at the implementation-defined expiry boundary;
- after deadline;
- after simulated clock rollback;
- after repeated restarts.

## Budget continuity

Accumulated budgets already persisted by RFC-0028 remain monotonic.

RFC-0037 requires explicit tests for:

- step budget;
- model-call budget;
- tool-call budget;
- byte budget;
- token budget;
- duration budget;
- integrated run budgets projected through RFC-0036 where applicable.

A restart cannot restore consumed budget.

An unknown checkpoint mutation cannot credit consumed work twice or erase consumed work.

When exact budget continuity cannot be proven, recovery fails closed rather than
choosing a larger remaining value.

Stricter current limits may reduce remaining budget.

Looser current limits do not automatically enlarge the original admitted budget for
an existing run unless a separate future RFC explicitly defines and authorizes such migration.

## Cancellation continuity

Cancellation is durable intent, not process-local intent.

RFC-0037 requires recovery to honor any current cancellation state before starting
new model or tool work.

Tests must cover:

- cancellation before crash;
- cancellation recorded while another worker is down;
- crash during cancellation transition;
- stale worker attempting work after cancellation;
- cancellation while an external attempt is indeterminate;
- cancellation followed by restart;
- repeated restart of a cancelled terminal run.

Cancellation cannot erase evidence needed to reconcile an indeterminate external effect.

## Retention and cleanup hardening

RFC-0028 retention remains authoritative.

RFC-0037 requires race evidence for:

- cleanup versus active lease;
- cleanup versus lease acquisition;
- cleanup versus terminal transition;
- cleanup versus protected-payload read;
- cleanup versus reconciliation;
- stale cleanup worker after newer fencing;
- repeated idempotent cleanup;
- tombstone retention expiry;
- restored stale active record after terminal tombstone.

Cleanup must remain bounded and content-free in routine diagnostics.

## Backup restore and anti-resurrection

A restored backup may contain an older active record that predates a terminal state
known by a newer store generation.

Where the durable store supports freshness metadata, Phoenix must persist or compare
a monotonic restore/store generation sufficient to detect obvious rollback.

When a newer tombstone or generation proves the restored active record is stale,
automatic recovery rejects resurrection.

When freshness cannot be established safely, Phoenix marks the candidate unavailable
for automatic recovery and requires explicit administrative handling.

The implementation must not assume that "latest timestamp wins".

## Repeated recovery failure

One recovery failure must not automatically create unbounded recovery traffic.

The coordinator must enforce finite:

- startup recovery pages;
- recovery attempts per run;
- recovery epochs;
- reconciliation attempts;
- lease renewal work;
- worker concurrency;
- queue depth;
- backoff/next-eligibility bookkeeping where applicable.

The exact retry scheduling remains an implementation detail subject to existing
runtime lifecycle rules.

A run that exhausts automatic recovery attempts moves to a safe paused/terminal
disposition already allowed by the durable state machine; RFC-0037 does not add a
parallel state machine for retry exhaustion.

## Observability

Reliability observability remains content-free by default.

Approved safe categories may include:

- run identifier;
- checkpoint sequence;
- durable version;
- fencing generation;
- recovery epoch category;
- fixed fault-point identifier in deterministic tests;
- mutation outcome category;
- compatibility category;
- deadline category;
- remaining-budget category;
- stale-worker rejection category;
- retention/cleanup category;
- restore-generation category;
- bounded counts and durations.

Routine output must exclude:

- prompts;
- model responses;
- raw tool arguments;
- raw tool results;
- browser/network/memory/workspace content;
- credentials;
- secret references;
- approval tokens;
- protected payload plaintext;
- protected payload ciphertext;
- raw external reconciliation evidence;
- raw exceptions that may contain sensitive data.

Fault injection identifiers are test diagnostics, not external control inputs.

## Administration

Existing durable administration remains authoritative.

RFC-0037 may add safe read-only reliability diagnostics such as:

- whether automatic recovery is paused;
- current lease presence;
- fencing generation;
- bounded recovery failure count;
- last safe recovery category;
- restore ambiguity category;
- deadline-expired category;
- budget-exhausted category.

Any mutation continues to use the existing exact durable administration,
authorization, confirmation, and audit boundaries.

There is no "force replay" administration operation.

## Compatibility

RFC-0037 is additive hardening.

When durable configuration is omitted:

- no reliability fault injector is created;
- no recovery worker is created by this RFC;
- no new persistence occurs;
- ordinary RFC-0027 agent execution remains unchanged.

When integrated execution is omitted:

- RFC-0036 integrated execution remains absent;
- durable-agent hardening may still apply to explicitly configured RFC-0028 durable runs.

Existing durable records must remain readable unless an explicit schema migration is
introduced and separately tested.

The implementation slices remain on package version `0.36.0`.

Only the release-finalization slice changes the package version to `0.37.0`.

Tagging, artifact publication, checksums, and GitHub Release publication are separate
release actions after merge and green post-merge CI.

## Implementation guidance

Expected implementation work should primarily harden existing durable surfaces such as:

- `src/phoenix_os/agent/durable_codec.py`;
- `src/phoenix_os/agent/durable_memory.py`;
- `src/phoenix_os/agent/durable_sqlite.py`;
- `src/phoenix_os/agent/durable_lease.py`;
- `src/phoenix_os/agent/durable_recovery.py`;
- `src/phoenix_os/agent/durable_attempts.py`;
- `src/phoenix_os/agent/durable_reconciliation.py`;
- `src/phoenix_os/agent/durable_runtime.py`;
- `src/phoenix_os/agent/durable_worker.py`;
- `src/phoenix_os/agent/durable_retention_worker.py`;
- RFC-0036 integrated durable projection/recovery surfaces where reliability evidence
  requires integration coverage.

The exact touched files must be decided slice by slice from current source state.

A slice must not broaden scope simply because an adjacent module is convenient.

## Test strategy

All reliability tests must be deterministic and network-free.

The suite should prefer:

- deterministic fake clocks;
- deterministic fault injectors;
- in-memory durable stores for exhaustive interleavings;
- SQLite persistent-store tests for transaction/reopen behavior;
- subprocess fixtures only where process loss itself is the property under test;
- explicit expected versions and fencing generations;
- exact checkpoint digests;
- exact attempt identifiers;
- fixed concurrency barriers rather than sleep-based races.

Tests must avoid timing assertions based on scheduler luck.

A race test that passes only because one thread "usually wins" is not acceptable.

## Reliability matrix

The final RFC-0037 adversarial suite must cover combinations across:

```text
STORE
  memory
  sqlite

RECOVERY POINT
  safe checkpoint
  approval wait
  after PREPARED
  after STARTED
  indeterminate model
  indeterminate tool
  terminal state

OWNERSHIP
  single worker
  lease renewal loss
  takeover
  concurrent recoverers
  stale worker

PERSISTENCE OUTCOME
  committed
  not committed
  unknown outcome
  version conflict
  corrupted/truncated state

LIVE CHANGE
  no change
  policy denied
  tool removed
  schema changed
  effect class changed
  profile generation changed
  model/provider changed
  stricter limits
  expired deadline
  cancellation

RETENTION
  active
  expiring
  cleanup race
  tombstone present
  stale backup restored
```

The matrix does not require a literal Cartesian product of every row.

It requires reviewed pairwise and high-risk multi-factor coverage sufficient to prove
every invariant and every distinct unsafe transition class.

## Release validation

RFC-0037 must add a named package/reliability gate before release finalization.

Expected shape:

```text
python scripts/check_reliability_release.py
```

The exact script name may be adjusted during implementation only if the final RFC,
CI, release notes, and tests agree.

The gate must:

- discover the complete RFC-0037 reliability regression surface;
- run deterministic fault-injection tests;
- run checkpoint corruption/truncation tests;
- run fencing/takeover tests;
- run concurrent recoverer tests;
- run indeterminate/reconciliation tests;
- run live-revalidation tests;
- run deadline/budget/cancellation continuity tests;
- run retention/anti-resurrection tests;
- run integrated durable recovery coverage;
- remain network-free;
- validate wheel and sdist packaging where new modules are added;
- prove no test-only fault injector is enabled by default in packaged runtime;
- participate in the repository-wide `scripts/check.ps1` gate.

The final release slice must preserve all prior named release gates.

## Slice plan

### Slice 1 - Reliability contracts and deterministic fault injection

- [ ] Define the minimal internal reliability classifications needed for mutation outcomes
- [ ] Add a deterministic Phoenix-owned fault-injection seam
- [ ] Add a no-op production implementation
- [ ] Prove the injector is absent from ordinary production composition
- [ ] Add fake-clock and deterministic interleaving utilities where current fakes are insufficient
- [ ] Add baseline crash-boundary tests without changing durable authority semantics
- [ ] Preserve package version 0.36.0

### Slice 2 - Checkpoint and durable-mutation integrity

- [ ] Harden exact handling of committed/not-committed/unknown mutation outcomes
- [ ] Re-read and compare after ambiguous durable writes
- [ ] Add corruption, truncation, substitution, rollback, sequence, and digest adversarial tests
- [ ] Add SQLite reopen tests around Phoenix-owned transaction boundaries
- [ ] Prove no malformed checkpoint is heuristically repaired
- [ ] Prove budget/checkpoint state cannot move backward after ambiguous writes
- [ ] Preserve RFC-0028 checkpoint/state-machine contracts

### Slice 3 - Lease fencing, takeover, and concurrent recoverers

- [ ] Exhaustively reject stale-worker mutation after newer fencing generation
- [ ] Cover completion, cancellation, reconciliation, cleanup, and terminalization paths
- [ ] Add deterministic two-recoverer interleaving tests
- [ ] Prove candidate reads are advisory and authoritative re-read happens after lease acquisition
- [ ] Prove lease renewal loss stops new protected work
- [ ] Add bounded repeated-takeover coverage
- [ ] Preserve existing lease contract and generation semantics

### Slice 4 - Indeterminate effects and reconciliation under crash

- [ ] Add crash coverage around PREPARED/STARTED/terminal attempt recording
- [ ] Prove no transparent model or tool replay after STARTED
- [ ] Harden ambiguous external completion handling
- [ ] Add reconciliation crash-boundary tests
- [ ] Reject stale, duplicate, conflicting, or mismatched reconciliation
- [ ] Prove a later fresh attempt requires sufficient evidence that prior acceptance did not occur
- [ ] Preserve RFC-0028 reconciliation actions and state machine

### Slice 5 - Live revalidation after restart

- [ ] Revalidate current `agent.resume` authority
- [ ] Revalidate current agent/integrated profile generation
- [ ] Revalidate tool registry, effect class, schema, and resource resolver identity
- [ ] Revalidate model/provider compatibility
- [ ] Revalidate current approval state
- [ ] Revalidate payload-protection availability
- [ ] Prove policy/config changes during downtime win over persisted state
- [ ] Add integrated RFC-0036 durable recovery coverage
- [ ] Preserve downstream canonical authorization boundaries

### Slice 6 - Deadlines, cancellation, budgets, retention, and safe operations

- [ ] Prove total deadline does not reset after restart
- [ ] Prove downtime expiry blocks new protected work
- [ ] Prove all finite budgets remain monotonic across repeated restart
- [ ] Prove current stricter limits can reduce but not silently enlarge remaining budget
- [ ] Harden cancellation continuity
- [ ] Harden retention/cleanup lease races
- [ ] Harden tombstone anti-resurrection and stale-backup handling
- [ ] Add bounded recovery-failure/retry evidence
- [ ] Add content-free reliability diagnostics and administration status

### Slice 7 - Adversarial crash matrix, migration, threat review, and release gate

- [ ] Complete the reviewed reliability matrix across memory and SQLite stores
- [ ] Add multi-factor crash/restart scenarios
- [ ] Add deterministic soak/repeated-restart tests with finite bounds
- [ ] Write RFC-0037 threat-model and invariant review
- [ ] Write migration/rollback guidance for v0.36.0 -> v0.37.0
- [ ] Add architecture decisions only where the implementation introduces a durable design choice
- [ ] Add and wire the named reliability release gate
- [ ] Prove all previous release gates remain green
- [ ] Preserve package version 0.36.0

### Slice 8 - v0.37.0 release finalization

- [ ] Set package version to 0.37.0
- [ ] Finalize RFC status after all implementation slices pass
- [ ] Finalize changelog, README compatibility notes, release notes, and security review
- [ ] Run targeted reliability gates
- [ ] Run integrated-agent release gate
- [ ] Run all prior named release gates
- [ ] Run full `scripts/check.ps1`
- [ ] Run adversarial reliability matrix
- [ ] Build wheel and sdist and validate isolated offline installation
- [ ] Merge only after feature CI is green
- [ ] Require green post-merge `main` CI before release publication
- [ ] Keep tag, checksums, artifacts, and GitHub Release as separately controlled publication steps

## Acceptance

RFC-0037 may be accepted for Phoenix OS v0.37.0 only when all slices are complete and
the full repository quality gate passes.

Acceptance additionally requires executable evidence that:

- RFC-0028 remains the only durable-run state machine;
- RFC-0036 still reuses RFC-0028 rather than introducing a second recovery engine;
- every unknown durable mutation outcome is resolved by exact authoritative re-read;
- checkpoint corruption, truncation, rollback, substitution, and sequence ambiguity fail closed;
- stale workers cannot mutate after fencing takeover;
- concurrent recoverers cannot both become authoritative;
- crash after `STARTED` never causes transparent model/tool replay;
- indeterminate effects require reviewed evidence before a safe later attempt;
- policy and configuration changes during downtime are enforced on recovery;
- removed or materially changed tools/models/schemas/profiles fail recovery closed;
- expired approvals are never revived;
- deadlines never reset;
- consumed budgets never reset;
- cancellation survives restart;
- cleanup cannot race past current fencing or active lease ownership;
- terminal runs cannot be automatically resurrected from stale restored state;
- recovery loops remain finite;
- routine reliability output remains content-free;
- test-only fault injection cannot be enabled by ordinary production composition;
- durable configuration omitted preserves existing non-durable behavior;
- all RFC-0028, RFC-0036, and repository-wide regression gates remain green;
- package artifacts install and execute in isolated offline environments;
- no tag or release publication occurs before green post-merge `main` CI and explicit
  release authorization.
