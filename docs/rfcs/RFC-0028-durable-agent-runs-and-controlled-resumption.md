# RFC-0028: Durable Agent Runs, Checkpoints, and Controlled Resumption

- Status: Draft
- Target release: Phoenix OS v0.28.0
- Owners: Phoenix OS maintainers
- Depends on: RFC-0004, RFC-0005, RFC-0007, RFC-0009, RFC-0012,
  RFC-0013, RFC-0021, RFC-0026, and RFC-0027

## Summary

RFC-0028 defines optional durable agent runs that can persist bounded checkpoints,
survive process restarts, pause for external approval, and resume through an
explicitly authorized and deterministic recovery protocol.

Durability does not grant additional authority. Every resumed model turn and tool
invocation remains subject to fresh validation, current configuration, current
policy authorization, approval, limits, cancellation, and lifecycle controls.

The subsystem is disabled by default. When durable-agent configuration is omitted,
Phoenix OS preserves the behavior of v0.27.0.

A checkpoint is untrusted persisted data, not a continuation token, permission,
approval, credential, or proof that previous work succeeded. Recovery validates
the entire record, acquires a fenced lease, reconstructs only reviewed state, and
fails closed when execution may have crossed an external side-effect boundary.

## Motivation

RFC-0027 introduced a bounded secure agent loop but intentionally excluded
restart-resumable agent runs. Its initial Runtime is in-memory and terminates work
when the process stops.

Long-running or approval-dependent operations need a safe way to survive expected
shutdowns without restarting the entire run, repeating completed side effects, or
treating persisted model content as trusted authority.

A durable recovery boundary must distinguish work that is safely reconstructable
from work whose external result is unknown. Recovery must fail closed rather than
silently repeating a model call or tool invocation that may already have produced
a billable response, external communication, or mutation.

Persisted state must remain data rather than authority. A checkpoint cannot grant
permission to continue, invoke tools, consume approvals, select credentials, or
bypass current policy and configuration.

The design must also prevent two workers from simultaneously recovering the same
run. Lease ownership alone is insufficient because a paused or partitioned worker
may continue after its lease expires. Every mutation therefore requires a current
fencing generation.

## Goals

- Optional durability disabled by default
- Immutable and versioned durable-run contracts
- Bounded checkpoints with strict Phoenix-owned codecs
- Deterministic recovery after process restart
- Explicit pause, resume, reconciliation, and terminal states
- Fresh authorization when a run resumes
- Safe waiting for human approval
- Lease and fencing protection against concurrent recovery
- Explicit handling of indeterminate external side effects
- No automatic repetition of model turns or tool invocations
- Atomic checkpoint transitions and optimistic concurrency
- Bounded retention, cleanup, cancellation, and shutdown
- Content-free persistence and observability by default
- Optional protected payload persistence under explicit configuration
- Deterministic network-free recovery tests
- RuntimeAssembler lifecycle ownership
- Compatibility with Phoenix OS v0.27.0 when durability is omitted

## Non-goals

- Autonomous scheduled agents
- Persistent semantic memory
- Retrieval-augmented generation
- Persisting prompts, model responses, arguments, or tool results by default
- Transparent retry of model or tool execution
- Claiming exactly-once external side effects
- Parallel execution of one durable run by multiple workers
- Cross-node distributed consensus
- General-purpose workflow orchestration
- Arbitrary shell, filesystem, network, or operating-system authority
- Allowing checkpoints to preserve expired approvals or previous authorization
- Recovering arbitrary provider SDK objects
- Resuming an adapter at an arbitrary instruction boundary
- Treating encryption as authorization
- Making an indeterminate external effect automatically safe to repeat

## Terminology

- **Durable run:** an RFC-0027 agent run admitted for checkpoint persistence.
- **Checkpoint:** one immutable versioned snapshot of approved durable metadata.
- **Checkpoint sequence:** a strictly increasing per-run version.
- **Safe boundary:** a state where no model or tool call is active and recovery can
  continue without repeating external work.
- **Attempt:** one identified model-turn or tool-invocation execution attempt.
- **Indeterminate attempt:** an attempt whose external completion cannot be proven.
- **Lease:** time-bounded ownership of recovery or mutation authority for one run.
- **Fencing generation:** a monotonic value required on every durable mutation.
- **Resume request:** an authenticated request to continue one paused run.
- **Reconciliation:** an explicit operator or adapter-supported decision about an
  indeterminate attempt.
- **Protected payload:** explicitly enabled encrypted content needed to reconstruct
  model context; absent in the default profile.
- **Tombstone:** bounded terminal metadata retained after payload cleanup.

## Threat model

The durable subsystem treats all checkpoint bytes, persisted metadata, payload
references, protected payloads after decryption, model content, tool content,
approval state, lease records, timestamps, recovery requests, storage errors, and
external reconciliation evidence as untrusted until validated.

The implementation must address:

- checkpoint corruption, truncation, and unsupported versions;
- rollback to an older valid checkpoint;
- duplicate checkpoint sequence numbers;
- cross-run checkpoint substitution;
- forged run, step, call, attempt, or actor identifiers;
- model- or tool-controlled durable state fields;
- persisted policy decisions being reused as authority;
- approval replay after restart;
- expired approval consumption;
- stale configuration or removed tools;
- changed schemas, resources, providers, or models;
- concurrent recovery by multiple workers;
- stale workers writing after lease expiry;
- wall-clock rollback and lease ambiguity;
- model or tool execution interrupted after external submission;
- duplicate external side effects;
- unsafe operator reconciliation;
- payload disclosure from storage, logs, metrics, health, or backups;
- key rotation and protected-payload decryption failure;
- unbounded checkpoint growth;
- retention or cleanup races;
- cancellation and shutdown races;
- partial storage transactions;
- tombstone deletion followed by unintended resurrection;
- storage availability causing unsafe admission;
- adapters falsely claiming idempotency or completion;
- restored backups reintroducing old active runs;
- content injection through recovered tool results;
- recovery loops that never reach a terminal state.

Installed storage and tool adapters remain trusted Phoenix code. Persisted values,
external systems, model-controlled content, and all adapter responses remain
untrusted.

## Security invariants

1. Durable agent execution is disabled unless explicitly configured.
2. Enabling durability creates no run, tool, permission, approval, worker, payload,
   schedule, or external authority automatically.
3. Every durable run has one stable Phoenix-owned `DurableAgentRunId`.
4. Every checkpoint belongs to exactly one run and one immutable schema version.
5. Checkpoint sequences increase monotonically and cannot be reused.
6. A checkpoint is data and grants no execution or policy authority.
7. Persisted authorization decisions are informational only and are never reused.
8. Resume requires a fresh exact authorization decision.
9. Every resumed model turn still requires a fresh RFC-0026 `model.infer` decision.
10. Every resumed tool call still requires a fresh exact `tool.invoke` decision.
11. Current configuration, registry, schemas, limits, and policy always win over
    persisted metadata.
12. Removed or materially changed dependencies fail recovery closed.
13. Expired, consumed, mismatched, or revoked approvals cannot be restored.
14. Approval evidence remains bound to the exact current invocation.
15. A run may have at most one active lease holder.
16. Every lease acquisition creates a strictly increasing fencing generation.
17. Every checkpoint mutation requires the current fencing generation.
18. A stale worker cannot write, complete, cancel, or reconcile a run.
19. Checkpoint creation is atomic with the durable state transition it records.
20. Recovery never skips a checkpoint sequence silently.
21. Unsupported, malformed, oversized, or non-canonical checkpoints fail closed.
22. Safe-boundary recovery does not repeat completed model or tool attempts.
23. An attempt active at process loss becomes indeterminate unless completion is
    proven through a reviewed adapter-specific protocol.
24. Indeterminate model or tool attempts are never retried automatically.
25. Phoenix does not claim exactly-once external side effects.
26. Idempotency keys reduce risk but do not prove exactly-once execution.
27. Reconciliation requires exact authorization and approved evidence.
28. Operator reconciliation cannot rewrite tool, resource, arguments, actor, or
    attempt identity.
29. Protected payload persistence is absent by default.
30. Enabling protected payloads requires explicit configuration, bounded size,
    authenticated encryption, versioned keys, and finite retention.
31. Encryption does not replace policy, approval, or access control.
32. Plaintext protected payloads never enter logs, audit, metrics, health, events,
    filenames, policy resources, or administration responses.
33. Decryption failure never falls back to plaintext or automatic restart.
34. Checkpoint payload references cannot escape their configured namespace.
35. Retention and cleanup are finite and preserve terminal tombstones as configured.
36. Cleanup cannot delete an actively leased run.
37. A deleted terminal run cannot be resurrected by stale state.
38. Cancellation prevents new model and tool work.
39. Shutdown releases or expires leases within finite bounds.
40. Recovery, reconciliation, retention, and cleanup workers have bounded queues,
    concurrency, attempts, and duration.
41. Durable events contain fixed Phoenix-owned types and content-free metadata.
42. Public failures expose no prompt, response, arguments, result, credential,
    approval token, protected payload, encryption metadata, or raw exception.
43. Tool results remain untrusted after recovery.
44. Durable runs cannot recursively invoke durable agent recovery.
45. Existing Phoenix OS v0.27.0 behavior remains unchanged when durable-agent
    configuration is absent.

## Proposed contracts

RFC-0028 adds or extends these Phoenix-owned contracts:

- `DurableAgentRunId`
- `DurableRunStatus`
- `DurableRunVersion`
- `CheckpointId`
- `CheckpointSequence`
- `CheckpointSchemaVersion`
- `CheckpointDigest`
- `CheckpointEnvelope`
- `CheckpointMetadata`
- `CheckpointPayloadProfile`
- `ProtectedPayloadReference`
- `RecoveryPoint`
- `RecoveryDisposition`
- `ExecutionAttemptId`
- `ExecutionAttemptKind`
- `ExecutionAttemptStatus`
- `IndeterminateReason`
- `DurableLeaseId`
- `FencingGeneration`
- `DurableLease`
- `ResumeRequest`
- `ResumeReason`
- `ResumeDecision`
- `ReconciliationRequest`
- `ReconciliationEvidence`
- `ReconciliationDecision`
- `RetentionPolicy`
- `DurableRunTombstone`
- `DurableRunStore`
- `CheckpointCodec`
- `CheckpointProtector`
- `DurableLeaseManager`
- `DurableRecoveryCoordinator`
- `DurableAgentRuntime`
- `DurableRunObserver`
- `DurableRunAdministration`
- `DurableRunError`

All public contracts are immutable, bounded, provider-neutral, serializable through
strict Phoenix-owned codecs, and free from provider SDK, database driver, task,
callback, thread, file-handle, socket, or executable objects.

## Durable run identity and versioning

A durable run is created only after normal RFC-0027 admission and exact
`agent.run` authorization.

Its immutable identity includes:

- durable run identifier;
- original RFC-0027 run identifier;
- authenticated initiating actor identifier;
- configured agent identifier;
- creation time from the trusted clock;
- checkpoint schema version;
- initial configuration compatibility digest;
- finite total deadline;
- retention class;
- payload profile.

A mutable `DurableRunVersion` increases on every accepted transition. Store
operations compare the expected version and current fencing generation.

The run identifier, actor, configured agent, and payload profile cannot change
after creation.

## Durable state machine

The durable coordinator uses explicit states:

```text
CREATED
ACTIVE
CHECKPOINTING
PAUSED_APPROVAL
PAUSED_OPERATOR
PAUSED_SHUTDOWN
RECOVERING
RECONCILING
INDETERMINATE_MODEL
INDETERMINATE_TOOL
COMPLETED
FAILED
CANCELLED
EXPIRED
```

Terminal states are:

```text
COMPLETED
FAILED
CANCELLED
EXPIRED
```

Only reviewed transitions are permitted.

A normal durable lifecycle is:

```text
CREATED
-> ACTIVE
-> CHECKPOINTING
-> ACTIVE
-> PAUSED_APPROVAL
-> RECOVERING
-> ACTIVE
-> CHECKPOINTING
-> COMPLETED
```

A controlled shutdown may produce:

```text
ACTIVE
-> CHECKPOINTING
-> PAUSED_SHUTDOWN
-> RECOVERING
-> ACTIVE
```

Process loss during an external attempt produces:

```text
ACTIVE
-> INDETERMINATE_MODEL
```

or:

```text
ACTIVE
-> INDETERMINATE_TOOL
```

An indeterminate run can move only to `RECONCILING`, a safe terminal state, or a
reviewed resumed state when completion evidence is sufficient. It never moves
directly back to automatic execution.

Invalid transitions, version mismatches, duplicate terminal states, work after
termination, or missing attempt evidence fail closed.

## Safe checkpoint boundaries

The Runtime may create a resumable checkpoint only when:

- no model call is active;
- no tool adapter is active;
- no result stream is open;
- no approval is being consumed;
- the current state transition is complete;
- all accumulated limits are known;
- the next legal operation is deterministic;
- required continuation data is available under the configured payload profile.

Examples of safe boundaries include:

- after durable admission and before the first model turn;
- after validated model final output and before completion;
- after a validated tool result is incorporated into the next checkpoint;
- while waiting for an external approval;
- after a cooperative pause request;
- during controlled shutdown before new work starts.

Phoenix does not serialize Python stacks, coroutine frames, generators, provider
streams, callbacks, open transactions, sockets, or adapter-local execution state.

## Checkpoint envelope

Every checkpoint envelope contains bounded metadata:

- checkpoint schema version;
- durable run identifier;
- checkpoint identifier;
- strictly increasing sequence;
- expected previous checkpoint digest;
- durable run version;
- current durable state;
- RFC-0027 run and step identifiers;
- next expected operation category;
- accumulated step, call, byte, token, and duration budgets;
- active or last attempt metadata;
- configuration compatibility digest;
- tool-registry compatibility digest;
- model-provider compatibility digest;
- payload profile and optional protected-payload reference;
- trusted creation time;
- retention deadline;
- canonical envelope digest.

It excludes by default:

- prompts;
- model responses;
- raw tool arguments;
- tool results;
- credentials;
- secret references;
- approval tokens;
- endpoints;
- external response bodies;
- raw exceptions;
- provider SDK objects;
- executable state.

The envelope is canonical, bounded, duplicate-key rejecting, finite-number
validated, depth limited, and encoded as UTF-8 through a Phoenix-owned codec.

## Checkpoint chain and rollback detection

Each checkpoint includes the digest of the immediately previous accepted
checkpoint.

Recovery verifies:

- run identity;
- schema version;
- sequence continuity;
- previous digest linkage;
- canonical digest;
- durable run version;
- terminal-state consistency;
- payload reference consistency;
- retention state;
- tombstone status.

The store rejects sequence reuse, conflicting records, and updates based on an
older durable run version.

The chain detects accidental or unauthorized rollback within the active store
history. It is not a substitute for external signatures, trusted backups, audit,
or storage access control.

Restoring an older backup may reintroduce stale runs. Startup therefore compares
store generation metadata and tombstones where supported and requires explicit
administrative recovery when freshness cannot be established.

## Payload profiles

The initial design defines two profiles.

### Metadata-only

`METADATA_ONLY` is the default.

It persists only content-free envelope metadata. A run is resumable only when its
next context can be reconstructed by reviewed server-side components from stable
references already authorized for that run.

It never persists prompts, responses, raw arguments, or results.

### Protected content

`PROTECTED_CONTENT` is opt-in.

It may persist the minimum bounded Phoenix-owned continuation content required to
resume, including validated agent messages or validated tool-result data.

The protected payload:

- uses authenticated encryption;
- uses a versioned configured protection key;
- includes run, checkpoint, sequence, schema, and profile as associated data;
- has strict plaintext and ciphertext byte limits;
- is stored under an opaque server-owned reference;
- is never used as policy language;
- is decrypted only after authorization, lease acquisition, and envelope
  validation;
- is deleted according to finite retention;
- fails closed under missing keys, invalid tags, unsupported versions, or
  incompatible codecs.

Key rotation may support decrypt-old/encrypt-new under explicit configuration.
Recovery never rewrites a payload merely because it was read.

## Storage boundary

`DurableRunStore` is a Phoenix-owned protocol.

The initial reference adapter uses the existing State Store or a dedicated SQLite
adapter with atomic transactions and optimistic versions.

Required operations include:

- create one durable run;
- append one checkpoint conditionally;
- read the current checkpoint;
- read bounded checkpoint history;
- acquire, renew, and release a fenced lease;
- transition state conditionally;
- record an indeterminate attempt;
- record reconciliation;
- write a terminal tombstone;
- enumerate bounded recovery candidates;
- delete protected payloads under retention policy.

The store exposes no arbitrary query interface to models, tools, or callers.

Store writes are atomic per run. A storage failure before commit leaves the prior
checkpoint authoritative. A storage failure with unknown commit outcome makes the
coordinator re-read and compare exact versions rather than blindly repeat the
write.

## Leases and fencing

Recovery or mutation requires one durable lease.

A lease contains:

- run identifier;
- lease identifier;
- owner identifier;
- fencing generation;
- trusted acquisition time;
- finite expiry;
- finite renewal interval.

Acquisition atomically increments the fencing generation.

Every subsequent write includes:

- expected run version;
- lease identifier;
- fencing generation.

The store rejects writes from an expired, replaced, or lower generation.

Lease renewal does not change the fencing generation. Reacquisition after expiry
does.

A worker that loses lease renewal stops new model and tool work immediately. It
cannot mark the run complete or persist later results.

Wall-clock time alone is not used to prove exclusive ownership. Store-side
conditional mutation and fencing are authoritative.

## Recovery protocol

Startup does not automatically resume every stored run.

The coordinator:

1. loads a bounded page of eligible non-terminal runs;
2. validates envelope, version, digest chain, retention, and tombstone state;
3. acquires a fenced lease;
4. re-reads the current checkpoint under that lease;
5. verifies current configuration and dependency compatibility;
6. obtains fresh `agent.resume` authorization;
7. validates approval state when the run waits for approval;
8. decrypts protected content only when configured and authorized;
9. classifies the recovery point;
10. transitions to `RECOVERING`;
11. either resumes at one safe boundary, pauses for operator action, marks an
    indeterminate attempt, or terminates safely;
12. writes the resulting checkpoint conditionally.

No step trusts the pre-acquisition read as current.

A failed security or compatibility decision cannot be overridden by asking the
model to adapt.

## Resume authorization

A resume request requires:

```text
action: agent.resume
resource: durable-agent-run:<run-id>
```

Policy input may include only approved content-free metadata:

- authenticated actor;
- durable run identifier;
- configured agent identifier;
- current state;
- pause reason;
- age category;
- attempt category;
- effect classification;
- safe compatibility categories.

Prompts, responses, arguments, results, protected payloads, and raw exceptions are
not policy language.

Authorization to resume permits only recovery orchestration. It does not authorize
the next model turn or tool call.

Operator-initiated resume and automatic startup recovery may use distinct trusted
actors and policy rules.

## Configuration compatibility

Every checkpoint records bounded compatibility digests for:

- durable checkpoint schema;
- configured agent;
- model provider and model;
- tool descriptor set admitted for the run;
- input and output schemas;
- resource-resolver identities;
- effect classifications;
- limit profile;
- payload profile;
- relevant codec versions.

A digest mismatch is classified.

Compatible changes may include stricter limits that still permit the remaining
run.

Material changes fail closed, including:

- missing model provider or model;
- removed tool;
- changed tool effect class;
- incompatible schema;
- changed resource resolver;
- weaker required approval;
- unsupported checkpoint version;
- unavailable protection key.

Migration between checkpoint schema versions requires an explicit deterministic
migrator. A model or tool cannot migrate durable state.

## Approval waiting and recovery

A run may checkpoint while waiting for human approval.

The checkpoint may contain only bounded approval correlation metadata:

- approval request identifier;
- exact tool, resource, argument digest, run, step, call, actor, and expiry
  evidence already permitted by RFC-0027;
- no approval token;
- no approving credential.

After restart, the Runtime queries the trusted approval gate and validates current
state.

A still-valid exact unused approval may be consumed only through the normal
approval gate. The checkpoint itself never proves approval.

Expired, denied, consumed, altered, unavailable, or unverifiable approval state
causes a safe pause or terminal failure according to policy. It never causes
automatic tool execution.

## Execution attempt records

Every model turn and tool invocation has one stable `ExecutionAttemptId`.

Before external submission, the Runtime conditionally records:

```text
PREPARED
```

Immediately before handing control to the provider or adapter, it records:

```text
STARTED
```

After validated completion, it records one terminal category:

```text
SUCCEEDED
FAILED
CANCELLED
TIMED_OUT
```

The attempt record contains only bounded safe metadata and exact correlation
identifiers.

If process loss occurs after `STARTED` without a durable terminal record, recovery
classifies the attempt as indeterminate.

The absence of a success record is not proof of failure.

## Model-turn recovery semantics

Model inference can be billable, rate-limited, nondeterministic, or accepted by a
provider before the local process receives output.

A model attempt left in `STARTED` becomes `INDETERMINATE_MODEL`.

The Runtime does not automatically resubmit it.

A reviewed provider adapter may expose an exact status lookup only when the
provider offers a trustworthy request identifier and bounded retrieval protocol.
The lookup itself is separately authorized and cannot produce tool authority.

Possible reconciliation outcomes are:

- verified completed with one validated recoverable result;
- verified not accepted and safe to start a new attempt;
- verified failed terminally;
- still indeterminate.

Without sufficient evidence, the run remains paused or fails safely.

## Tool-invocation recovery semantics

Tool execution follows the same no-transparent-retry rule as RFC-0027.

A tool attempt left in `STARTED` becomes `INDETERMINATE_TOOL`.

The Runtime does not call the tool again automatically, including when it is
declared read-only.

A reviewed tool adapter may support:

- exact idempotency-key lookup;
- external operation status lookup;
- receipt verification;
- deterministic local transaction lookup;
- explicit compensating-action proposal.

These capabilities are declared in trusted configuration and cannot be invented by
the model.

A compensating action is a new exact tool invocation with independent validation,
authorization, approval, attempt identity, and audit. It is never an implicit
rollback.

## Reconciliation

Reconciliation requires:

```text
action: agent.reconcile
resource: durable-agent-run:<run-id>/attempt:<attempt-id>
```

A `ReconciliationRequest` contains:

- run and attempt identifiers;
- current fencing generation;
- indeterminate category;
- bounded evidence type;
- operator-selected reviewed disposition;
- no arbitrary replacement state.

Reviewed dispositions may include:

- `CONFIRM_SUCCEEDED`;
- `CONFIRM_FAILED`;
- `CONFIRM_NOT_STARTED`;
- `REMAIN_INDETERMINATE`;
- `CANCEL_RUN`;
- `FAIL_RUN`.

The strongest applicable policy and approval requirements apply.

`CONFIRM_SUCCEEDED` requires validated result evidence compatible with the exact
attempt. It cannot accept model-authored claims.

`CONFIRM_NOT_STARTED` permits a later fresh attempt only when evidence proves the
external system did not accept the original operation.

Every reconciliation is immutable, audited, checkpointed, and bound to one attempt.

## Limits, budgets, and admission

Durable limits are finite and combine with RFC-0027 limits. The most restrictive
applicable value wins.

Additional limits cover:

- maximum checkpoints per run;
- maximum checkpoint envelope bytes;
- maximum protected payload bytes;
- maximum checkpoint history bytes;
- maximum recovery attempts;
- maximum reconciliation attempts;
- maximum pause duration;
- maximum total durable lifetime;
- lease duration;
- lease renewal interval;
- recovery queue depth;
- concurrent recovery workers;
- retention duration;
- tombstone duration;
- cleanup batch size;
- cleanup duration;
- key-rotation batch size;
- startup recovery page size.

Accumulated RFC-0027 step, call, byte, token, and duration budgets are persisted and
never reset by restart.

A restart cannot create a new total deadline or larger budget.

Admission fails before creating protected payloads, acquiring model credentials, or
invoking tools when storage, protection, policy, or required dependencies are
unavailable.

## Cancellation

Cancellation requires current authorization and a fenced lease.

Cancellation:

1. transitions the run to a cancelling condition;
2. rejects new model and tool work;
3. signals active local work;
4. records an indeterminate attempt when external completion is unknown;
5. invalidates unused approvals when supported;
6. writes a terminal `CANCELLED` checkpoint only when safe;
7. otherwise preserves the indeterminate state for reconciliation;
8. releases capacity and the durable lease within finite bounds.

Cancellation does not prove an external side effect was prevented.

A cancelled run cannot be resumed.

## Controlled shutdown

Runtime shutdown:

1. stops durable admission and automatic recovery;
2. stops taking new recovery leases;
3. asks active runs to reach one safe checkpoint boundary;
4. stops starting model and tool attempts;
5. records indeterminate attempts when active external work cannot be proven
   terminal;
6. persists `PAUSED_SHUTDOWN` where safe;
7. releases leases;
8. closes payload protection, storage, and observers in reverse composition order;
9. completes within configured grace periods.

Shutdown does not wait indefinitely for approvals, providers, tools, storage, or
external reconciliation.

Partial startup rolls back deterministically and exposes no durable service until
storage, codecs, protection, leases, policy, and recovery validation succeed.

## Retention, cleanup, and tombstones

Retention is explicit and finite.

A policy may retain:

- active checkpoint metadata;
- bounded checkpoint history;
- protected payloads;
- terminal metadata;
- tombstones;
- audit facts under the independent audit policy.

Protected payload retention should be shorter than content-free metadata retention.

Cleanup:

- uses bounded pages;
- acquires or verifies exclusive cleanup authority;
- skips active leases;
- deletes payloads before or with their references atomically where supported;
- preserves terminal identity and anti-resurrection metadata;
- records safe audit facts;
- tolerates repeated execution without deleting active data.

A tombstone contains only:

- run identifier;
- terminal category;
- terminal version;
- final checkpoint digest;
- deletion generation;
- safe retention timestamps.

It contains no prompt, response, arguments, result, credential, or approval token.

## Secrets and protected payload keys

Protection keys are configured as versioned secret references through trusted
composition.

The Runtime leases the minimum required key only during payload encryption or
decryption and revokes the lease immediately afterward.

Key material never enters:

- checkpoints;
- payload references;
- policy resources;
- approval records;
- logs;
- metrics;
- health;
- Event Bus events;
- administration output;
- filenames.

Unknown key versions, revoked keys, invalid authentication tags, or ambiguous key
selection fail closed.

Key destruction may make retained payloads unrecoverable. Administration must show
only safe counts and key-version categories before destructive rotation or
retirement.

## Audit, observability, and events

Safe audit facts cover:

- durable-run admission;
- checkpoint creation and rejection category;
- lease acquisition, renewal failure, and release;
- recovery admission and outcome;
- resume authorization;
- compatibility failure category;
- protected-payload creation and deletion category;
- approval wait and recovery category;
- indeterminate attempt detection;
- reconciliation request and disposition;
- cancellation;
- retention and cleanup;
- startup and shutdown;
- configuration failure.

Approved metadata may include:

- stable run, checkpoint, attempt, and lease identifiers;
- checkpoint sequence and schema version;
- fencing generation;
- durable state;
- safe pause or terminal category;
- effect classification;
- compatibility category;
- payload profile;
- bounded counts, ages, sizes, and durations;
- digest values approved for correlation.

Safe output excludes:

- prompts;
- model responses;
- raw arguments;
- tool results;
- protected plaintext or ciphertext;
- payload storage paths;
- credentials;
- secret references;
- approval tokens;
- endpoint details;
- external response bodies;
- raw reconciliation evidence;
- internal exceptions.

Event Bus events use fixed Phoenix-owned event types with empty payloads and
content-free metadata.

## Configuration and RuntimeAssembler integration

Durable composition is optional and requires RFC-0027 agent composition.

Configuration declares:

- whether durable runs are enabled;
- store adapter and namespace;
- checkpoint schema and codec;
- payload profile;
- protection-key references when protected content is enabled;
- lease and fencing parameters;
- recovery admission and worker limits;
- pause and durable-lifetime limits;
- retention and tombstone policy;
- reconciliation capabilities;
- compatibility rules;
- safe observability configuration;
- bounded startup and shutdown limits.

`RuntimeAssembler` validates configuration and composes:

- durable store;
- checkpoint codec;
- optional checkpoint protector;
- lease manager;
- recovery coordinator;
- durable agent Runtime;
- observer;
- administration boundary;
- retention worker.

No autonomous agent is created or scheduled.

The recovery worker examines only existing eligible durable runs. It cannot create
new agent goals or widen authority.

When durable configuration is omitted, no durable services, workers, stores,
payloads, leases, or events are created.

## Administration

Maintainer administration may expose:

- safe durable-run identifiers;
- current state and pause category;
- checkpoint sequence;
- age and retention category;
- payload profile without payload content;
- lease presence and fencing generation;
- indeterminate attempt category;
- compatibility category;
- bounded recovery and cleanup health;
- safe counts;
- authorized pause, resume, cancel, reconcile, and cleanup operations.

Administration excludes:

- prompts;
- responses;
- arguments;
- results;
- protected payloads;
- credentials;
- secret references;
- approval tokens;
- raw external evidence;
- raw exceptions.

Destructive cleanup, reconciliation, forced failure, and payload deletion require
exact actions, recent step-up authentication for human operators, confirmation, and
audit.

Machine administration is disabled by default and requires exact service-account
scopes and resources before exposure.

## Compatibility and migration

Durable-agent configuration begins absent and disabled.

When omitted, Phoenix OS preserves all v0.27.0 agent, inference, Runtime, Control
Plane, Dashboard, service-account, webhook, inbound-event, session, jobs,
workflows, audit, secrets, Event Bus, network, TLS, and persistence behavior.

Upgrade creates no durable run, checkpoint, payload, key lease, recovery worker,
permission, approval, model call, tool call, or external access.

The implementation slices remained on `0.27.0`. The release-preparation slice
sets the package version to `0.28.0`; final tag, artifacts, and checksums remain
reserved for the publication step.

Migration must support:

- disabled configuration;
- deterministic storage and codec validation;
- metadata-only canary runs;
- optional protected-payload validation;
- conservative lease and recovery limits;
- policy setup for resume and reconciliation;
- retention setup;
- content-free observation;
- immediate rollback by disabling new durable admission and recovery;
- explicit handling of already persisted runs.

Disabling durability stops new durable admission and automatic recovery. It does
not delete existing records automatically and does not disable ordinary in-memory
RFC-0027 agent execution or RFC-0026 inference.

Rollback documentation must distinguish:

- disabling new durable runs;
- pausing recovery workers;
- preserving records for later compatible recovery;
- exporting safe diagnostics;
- explicitly cancelling or failing retained runs;
- deleting protected payloads under confirmed retention procedures.

The staged upgrade and disable-first rollback procedure is recorded in
[`v0.27.0-to-v0.28.0-durable-agent.md`](../migrations/v0.27.0-to-v0.28.0-durable-agent.md).

The principal durable architecture decisions are recorded in five accepted ADRs:

- [`ADR-0021`](../adrs/ADR-0021-untrusted-canonical-chained-durable-checkpoints.md)
  — checkpoints remain untrusted canonical chained data and never authority.
- [`ADR-0022`](../adrs/ADR-0022-fenced-leases-and-conditional-durable-mutation.md)
  — monotonic fencing plus conditional store mutation rejects stale workers.
- [`ADR-0023`](../adrs/ADR-0023-controlled-recovery-and-explicit-indeterminate-reconciliation.md)
  — safe-boundary recovery uses fresh authority and explicit indeterminate reconciliation.
- [`ADR-0024`](../adrs/ADR-0024-opt-in-protected-payloads-and-content-free-durable-operations.md)
  — metadata-only is default; protected continuation content is explicit and bounded.
- [`ADR-0025`](../adrs/ADR-0025-opt-in-runtime-owned-durable-lifecycle-retention-and-administration.md)
  — durability remains opt-in and Runtime-owned with bounded retention and administration.

The formal threat-model and security-invariant review is recorded in
[`RFC-0028-durable-agent-threat-model-review.md`](../security/RFC-0028-durable-agent-threat-model-review.md). It maps checkpoint
corruption, rollback, substitution, stale authority, approval replay, fencing
races, indeterminate external work, protected-payload disclosure, retention and
cleanup races, safe operational output, and v0.27.0 compatibility to executable
regression suites and residual risks.

## Durable-agent release validation

The RFC-0028 release candidate must pass the named durable-agent package gate:

```text
python scripts/check_durable_agent_release.py
```

The gate discovers the complete `test_agent_durable_*.py` regression surface
and the RFC-0028 migration, ADR, security-review, and release-gate suites. It
builds and inspects wheel and sdist artifacts, rejects unsafe archive paths and
sensitive file types, verifies that every `durable_*.py` module is shipped,
rebuilds a wheel from the validated sdist, and installs both wheel forms with
`--no-deps --no-index` in isolated offline environments.

Packaged smoke execution runs with isolated Python mode and no source-tree
imports. It validates canonical metadata-only checkpoint encoding, chained
durable-store mutation, stale-worker rejection after fencing generation changes,
and the exact `agent.resume` and `agent.reconcile` action/resource names.

The gate reads the current package version from `pyproject.toml`. Per the
compatibility rule above, implementation slices remain on v0.27.0 and the
package changes to v0.28.0 only in the final release slice.

Release metadata is recorded in
[`docs/releases/v0.28.0.md`](../releases/v0.28.0.md), and the package version is
`0.28.0`. This preparation does not claim the final `v0.28.0` tag, published
wheel/sdist assets, or `SHA256SUMS`; those remain the final checklist item.

## Slice plan

### Slice 1 - Contracts, codecs, checkpoint store, and deterministic fakes

- [ ] Immutable durable-run, checkpoint, attempt, lease, and error contracts
- [ ] Strict canonical checkpoint envelope codec
- [ ] Metadata-only and protected-content payload profiles
- [ ] In-memory deterministic durable store
- [ ] Atomic version and sequence enforcement
- [ ] Deterministic checkpoint protector fake
- [ ] Contract, codec, corruption, rollback, and bound tests

### Slice 2 - Leases, fencing, state machine, and recovery

- [ ] Durable state machine and reviewed transitions
- [ ] Lease acquisition, renewal, expiry, and fenced mutation
- [ ] Safe checkpoint-boundary enforcement
- [ ] Startup recovery coordinator
- [ ] Configuration compatibility validation
- [ ] Stale-worker, split-brain, rollback, and race tests
- [ ] Bounded recovery admission and worker lifecycle

### Slice 3 - Pause, approval, attempts, and reconciliation

- [ ] Approval-wait checkpoints and current-state revalidation
- [ ] Model and tool execution attempt records
- [ ] Indeterminate model and tool recovery semantics
- [ ] Exact `agent.resume` and `agent.reconcile` authorization
- [ ] Reviewed adapter status lookup boundary
- [ ] Operator reconciliation dispositions
- [ ] No-transparent-retry and duplicate-side-effect tests
- [ ] Cancellation and controlled-shutdown tests

### Slice 4 - Persistence, Runtime, observability, and administration

- [ ] Durable reference storage adapter
- [ ] Optional authenticated protected-payload persistence
- [ ] RuntimeAssembler composition and deterministic rollback
- [ ] Retention, cleanup, and tombstones
- [ ] Content-free audit, metrics, logs, health, and Event Bus events
- [ ] Maintainer durable-run administration
- [ ] Compatibility tests with durable configuration omitted
- [ ] Bounded startup and shutdown ordering

### Slice 5 - Migration, architecture decisions, and v0.28.0

- [x] Migration guidance and rollback procedure
- [x] Architecture Decision Records
- [x] Threat-model and security-invariant review
- [x] Durable-agent release gate
- [x] Wheel and sdist isolated offline installation tests
- [x] Release notes and package version 0.28.0
- [ ] Tag, artifacts, and checksums

## Acceptance

RFC-0028 may be accepted for Phoenix OS v0.28.0 only when every slice is complete
and the full quality gate passes.

Acceptance additionally requires demonstrated evidence that:

- checkpoints grant no authority;
- resume, model, tool, and reconciliation operations receive independent current
  policy decisions;
- current configuration and stricter limits override persisted state;
- stale workers cannot mutate after fencing changes;
- checkpoint corruption, rollback, substitution, and unsupported versions fail
  closed;
- process loss during active model or tool work never causes automatic retry;
- indeterminate side effects require reviewed reconciliation;
- approvals remain exact, current, single-use, and replay-resistant after restart;
- protected content is absent by default and remains encrypted, bounded, and
  excluded from safe output when enabled;
- restart does not reset budgets or deadlines;
- retention and cleanup cannot delete active runs or resurrect terminal runs;
- cancellation and shutdown are bounded;
- durable configuration omitted preserves Phoenix OS v0.27.0 behavior;
- package artifacts install and execute in isolated offline environments.
