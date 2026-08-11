# RFC-0029: Secure Multi-Agent Coordination and Delegation

- Status: Draft
- Target release: Phoenix OS v0.29.0
- Owners: Phoenix OS maintainers
- Depends on: RFC-0004, RFC-0005, RFC-0007, RFC-0009, RFC-0012, RFC-0015, RFC-0016, RFC-0026, RFC-0027, and RFC-0028

## Summary

RFC-0029 defines optional, bounded, policy-controlled delegation from one Phoenix
agent run to another registered Phoenix agent.

Delegation creates work, never authority. A parent cannot transfer permissions,
approvals, credentials, tool grants, model grants, or prior policy decisions to a
child. Every child is independently admitted against current server-owned
configuration and current policy.

The subsystem is disabled by default. When coordination is omitted, Phoenix OS
preserves v0.28.0 behavior.

RFC-0029 does not replace RFC-0016 workflow graphs. RFC-0016 remains the mechanism
for predefined durable workflows; RFC-0029 covers bounded agent-to-agent
delegation created during an admitted agent run.

## Goals

- Optional coordination disabled by default
- Stable Phoenix-owned delegation and child-run identities
- Independent child admission and authorization
- Exact `agent.delegate` authorization
- No authority inheritance
- Server-owned child registry
- Bounded depth, fan-out, concurrency, child count, queue, and duration
- Root budgets that cannot grow by delegating
- Deterministic child lifecycle
- Bounded untrusted child results
- Cancellation/shutdown ownership
- Durable recovery without duplicate child creation
- Content-free observability
- RuntimeAssembler lifecycle ownership
- Compatibility with Phoenix OS v0.28.0 by omission

## Non-goals

- Autonomous peer discovery
- Unbounded swarms
- Distributed consensus
- Replacing workflow orchestration
- Shared mutable semantic memory
- Copying parent tools, approvals, or credentials to children
- Arbitrary provider orchestration objects
- Detached children that intentionally outlive the parent
- Exactly-once external side effects
- Generic shell, filesystem, network, browser, desktop, or OS authority

## Terminology

- **Parent run:** admitted run requesting delegation.
- **Child agent:** server-registered agent eligible for delegation.
- **Child run:** independently admitted run created for one delegation.
- **Delegation:** immutable request from parent to one child agent.
- **Delegation ID:** stable Phoenix-owned identity for one delegation.
- **Delegation depth:** edges from the root run.
- **Fan-out:** children created by one parent.
- **Delegation budget:** finite root-owned allowance reserved for child work.
- **Child result:** bounded untrusted data returned by a terminal child run.
- **Ancestor chain:** bounded Phoenix-owned lineage metadata.

## Threat model

The subsystem treats model-proposed child selection, delegation input, child
output, lineage, durable recovery state, registry data, and adapter responses as
untrusted until validated.

It must address authority laundering, approval/credential inheritance, arbitrary
child selection, recursion loops, fan-out explosions, budget multiplication,
duplicate child creation after restart, stale child configuration, cancellation
races, oversized results, prompt injection through child results, forged lineage,
cross-run result substitution, orphan children, and content leakage through safe
operational surfaces.

## Security invariants

1. Coordination is disabled unless explicitly configured.
2. Enabling it creates no run, permission, approval, credential, tool grant, model grant, schedule, or external authority.
3. Every delegation has one stable Phoenix-owned `DelegationId`.
4. Every child run has its own Phoenix-owned run identity.
5. Child agents come only from a server-owned allowlist.
6. Model content cannot construct arbitrary child implementations.
7. Every delegation requires a fresh exact `agent.delegate` authorization.
8. Delegation authorization is separate from `agent.run`, `model.infer`, `tool.invoke`, `agent.resume`, and `agent.reconcile`.
9. A parent transfers no policy authority to a child.
10. Parent permissions are never copied into the child security context.
11. Parent approvals are never reusable by a child.
12. Parent credentials are never copied to a child by default.
13. Every child is independently admitted using current configuration and policy.
14. Current registry and policy always win over persisted delegation metadata.
15. Removed or materially changed child configurations fail closed.
16. Delegation depth has a finite configured maximum.
17. Per-parent fan-out has a finite configured maximum.
18. Total children per root run have a finite configured maximum.
19. Concurrent child execution has a finite configured maximum.
20. Every delegation has a finite deadline.
21. Child queue capacity is bounded.
22. Delegation cannot increase the root run's total configured budget.
23. Child budgets are reserved from or capped by remaining root allowance.
24. Unused child allowance cannot exceed root limits.
25. The ancestor chain is Phoenix-owned and validated.
26. Delegation cycles fail closed.
27. Nested delegation requires policy permission and remaining depth.
28. One `DelegationId` cannot create two distinct child runs.
29. Durable recovery never silently duplicates an already-created child.
30. Parent/child linkage is atomic with child creation metadata.
31. Cross-run child-result substitution fails closed.
32. Child output is untrusted data and never becomes policy or executable authority.
33. Child results have strict size/depth/schema bounds.
34. Parent aggregation is deterministic and bounded.
35. Child terminal states are immutable.
36. Parent cancellation prevents new child creation.
37. Parent cancellation propagates to active owned children.
38. Shutdown drains or cancels children within finite bounds.
39. Detached children are not supported in the initial version.
40. Coordination events use fixed Phoenix-owned event types.
41. Logs, audit, metrics, health, and administration expose content-free metadata only.
42. Public failures expose no prompt, child input/result, credential, approval token, secret, provider body, or raw exception.
43. Provider SDK orchestration objects never appear in public contracts.
44. Coordination grants no generic shell, filesystem, network, browser, desktop, or OS authority.
45. Existing Phoenix OS v0.28.0 behavior remains unchanged when coordination configuration is absent.

## Proposed contracts

- `DelegationId`
- `DelegationDepth`
- `DelegationStatus`
- `DelegationRequest`
- `DelegationDecision`
- `DelegationLimits`
- `DelegationBudget`
- `DelegationLineage`
- `DelegatedChildRun`
- `DelegatedChildResult`
- `ChildResultStatus`
- `CoordinationPolicy`
- `AgentDelegationRegistry`
- `AgentDelegationCoordinator`
- `AgentCoordinationRuntime`
- `AgentCoordinationObserver`
- `AgentCoordinationAdministration`
- `AgentCoordinationError`

All public contracts are immutable, bounded, provider-neutral, and contain no
provider SDK, task, callback, thread, file-handle, socket, database-driver, or
executable objects.

## Authorization boundary

The exact initial action and policy resource shape are:

```text
agent.delegate
agent-delegation:<namespace>/parent:<parent-agent-id>/child:<child-agent-id>
```

The policy resource is derived only from the server-owned coordination namespace
and trusted parent/child `AgentId` values. It contains no model text, child input,
credential, approval, endpoint, provider body, or other caller-controlled content.

A successful decision permits only admission of the specified child delegation.
It does not imply model, tool, approval, credential, resume, reconciliation, or
nested-delegation authority.

## Child registry and lineage

Delegable agents are server-registered. Model output may request a registered
identifier but cannot register, replace, or mutate an agent.

Every child receives a bounded Phoenix-owned ancestor chain. The coordinator
rejects malformed lineage, depth overflow, disallowed cycles, lineage inconsistent
with the authenticated parent, and reused delegation identity bound to different
lineage.

## Bounded delegation

Before child creation, Phoenix validates depth, fan-out, total child count,
concurrency, queue capacity, deadline, input bytes, result bytes, result depth,
model/tool budgets, and remaining root allowance.

Delegation cannot manufacture additional authority or budget.

## Coordinator and bounded lifecycle

The in-memory coordinator is responsible only for authorization, finite admission,
stable child identity, root-budget reservation, and deterministic lifecycle state.
It does not execute child agents directly.

The reviewed lifecycle is:

```text
REQUESTED
-> AUTHORIZED
-> ADMITTED
-> RUNNING
-> COMPLETED
```

`FAILED`, `CANCELLED`, and `EXPIRED` are immutable terminal outcomes. Invalid,
non-monotonic, duplicate, or post-terminal transitions fail closed.

Before admission the coordinator enforces the most restrictive applicable values
for:

- delegation depth;
- per-parent fan-out;
- total children per root;
- concurrent children;
- queue capacity;
- request deadline;
- child budget;
- root aggregate budget.

One `DelegationId` is permanently bound to at most one child-run identity in one
coordinator lifetime. Duplicate identities are rejected instead of creating a
second child.

Root budget reservations are cumulative. Completing a child releases concurrency
capacity but does not restore already-reserved model turns, tool calls, tokens,
bytes, or duration, so delegation cannot manufacture additional root allowance.

Cycle prevention remains a pre-admission invariant of the Phoenix-owned lineage
and registry boundary.

## Child results

### Bounded child execution, results, and Runtime ownership

Child input remains untrusted data. Before a delegated child starts, Phoenix
canonically encodes the structured delegation input and derives a new
`AgentRunRequest` from the reviewed child registry entry. The child request uses
the coordinator-owned `AgentRunId`, current provider/model configuration, and an
`AgentLimits` value narrowed to the reserved `DelegationBudget`. No parent
permission, approval, credential, policy decision, tool grant, or model grant is
copied into the child request.

Child run results are also untrusted. Phoenix binds every result to the exact
delegation and child-run identity, maps it to a finite `ChildResultStatus`, and
enforces delegated result-byte and structured-depth bounds before the parent may
consume it. Failed, cancelled, and timed-out children expose only a bounded safe
error code and never a partial output.

Multi-child aggregation is deterministic: results are ordered by stable
`DelegationId`, duplicate delegation or child-run identities fail closed, and
the aggregate has explicit result-count and encoded-byte limits.

One Runtime-owned cancellation token covers the entire queued-to-running child
operation. Parent cancellation therefore removes queued work before admission
and propagates to an active child. Runtime shutdown cancels every owned queued or
running operation, drains for a finite grace period, and force-cancels only
within a second finite bound. Detached children remain unsupported.

Coordination is explicit opt-in composition through
`create_agent_coordination_runtime_stack`. The existing
`create_agent_runtime_stack` path is unchanged by omission. The coordination
stack exposes a lifecycle component compatible with Phoenix Runtime
`ComponentSpec` ownership, plus content-free observer and administration
surfaces. Operational observations contain stable identifiers, statuses,
durations, and safe error codes only; they never contain child input or output.


Child input and output are bounded, schema-validated, untrusted data. Child output
never carries executable policy, approvals, credentials, or direct authority.

## Cancellation and lifecycle

The parent Runtime owns all children. Parent cancellation prevents new child
admission and requests cancellation of active children. Shutdown uses the same
finite ownership model. Detached children are not supported initially.

## Durable integration

With RFC-0028 enabled, parent checkpoints record content-free delegation identity
and child links. Child identity remains stable across restart. Recovery re-reads
current state and never silently recreates an already-admitted child.

RFC-0029 does not weaken RFC-0028 fencing, checkpoint, retention, or reconciliation
invariants.

## Compatibility

When coordination configuration is omitted, no coordination registry, coordinator,
queue, or worker is created, and RFC-0027/RFC-0028 behavior remains unchanged.

## Durable coordination recovery

Durable coordination persists content-free delegation identity before child
execution can begin. The persisted binding includes the stable `DelegationId`,
parent/root identities, reviewed child identity, exactly one Phoenix-owned
`child_run_id`, bounded reserved budget, request digest, compatibility digest,
lifecycle status, optimistic version, recovery classification, and timestamps.
Raw delegation input and child output are not stored in this coordination
metadata.

Persistence follows compare-and-swap versioning. `DelegationId` and
`child_run_id` are unique, immutable identities. A replayed request must match
the original request digest and the current reviewed child compatibility digest
before the same child identity can be admitted again.

Startup recovery is deliberately asymmetric:

- `REQUESTED`, `AUTHORIZED`, and `ADMITTED` records become `RECOVERABLE`;
- `RUNNING` records become `INDETERMINATE`;
- expired non-terminal records become terminal `EXPIRED`;
- terminal records are never recovery candidates.

Recoverable work may be re-submitted only with the exact original request
identity. Phoenix then re-authorizes against current policy and current registry
configuration and reuses the already-persisted `child_run_id`. Recovery never
allocates a replacement child identity for the same `DelegationId`.

Indeterminate running work is never replayed automatically. Reconciliation
requires bounded content-free evidence and an exact expected durable version.
Only evidence-backed `CONFIRM_NOT_STARTED` may return an indeterminate record to
recoverable `ADMITTED` state. Evidence may instead confirm completed, failed, or
cancelled terminal state. Without such evidence, the record remains
indeterminate.

The reference stores are an atomic in-memory implementation for deterministic
testing and a dedicated-file SQLite implementation using WAL, `synchronous =
FULL`, unique child identities, and optimistic compare-and-swap updates. The
SQLite store persists only coordination metadata and is intentionally separate
from child prompts/results and provider payloads.

Lifetime accounting is durable. Terminal child records continue to consume the
root total-child allowance, per-parent fan-out, and reserved root budget after a
restart. New reservations are checked atomically with record creation; SQLite
performs that check inside the same `BEGIN IMMEDIATE` transaction as the insert.
A restart therefore never restores consumed delegation capacity or budget.

Recoverable replay is claimed with optimistic compare-and-swap before local
admission. Two owners racing the same recoverable `DelegationId` cannot both
acquire it. If any sibling for the same root remains `INDETERMINATE`, Phoenix
blocks new or resumed work for that root until reconciliation resolves the
unknown execution state.

`create_durable_agent_coordination_runtime_stack` is explicit opt-in composition.
Its lifecycle runs recovery before the coordination runtime accepts new work and
closes the durable store only after bounded runtime shutdown. Existing
non-durable coordination and the v0.28 agent stack remain unchanged by omission.


## Release-candidate hardening

Phoenix OS v0.29.0 release-candidate evidence is maintained in:

- `docs/security/RFC-0029-multi-agent-threat-model-review.md`;
- `docs/migrations/v0.28.0-to-v0.29.0-multi-agent.md`;
- ADR-0048 through ADR-0051;
- `docs/releases/v0.29.0.md`; and
- `scripts/check_multi_agent_release.py`.

The named gate builds and validates wheel and sdist archives, rebuilds a wheel
from the validated sdist, and installs both wheel forms with `--no-deps
--no-index` in isolated environments before executing the packaged coordination
surface without source-tree imports. Tagging, final artifacts, checksums, and RFC
acceptance remain separate final-publication actions.

## Slice plan

### Slice 0 - RFC foundation and executable specification

- [x] Draft RFC-0029 with explicit security invariants
- [x] Add RFC structure and regression tests
- [x] Establish exact action/resource naming
- [x] Confirm compatibility-by-omission contract

### Slice 1 - Contracts, registry, and authorization

- [x] Immutable delegation contracts
- [x] Bounded identifiers, statuses, lineage, limits, and budgets
- [x] Server-owned child-agent registry
- [x] Exact `agent.delegate` authorization boundary
- [x] Deterministic contract and authorization tests

### Slice 2 - Coordinator and bounded lifecycle

- [x] Delegation coordinator
- [x] Child admission and lifecycle state machine
- [x] Depth, fan-out, concurrency, queue, deadline, and budget enforcement
- [x] Cycle prevention and duplicate-identity rejection
- [x] Deterministic race and limit tests

### Slice 3 - Results, cancellation, and Runtime ownership

- [x] Bounded child input/result validation
- [x] Deterministic aggregation boundary
- [x] Parent cancellation propagation
- [x] Controlled shutdown and finite draining
- [x] RuntimeAssembler opt-in composition
- [x] Content-free observer and administration

### Slice 4 - Durable coordination and recovery

- [x] Durable parent/child linkage
- [x] Stable child identity across restart
- [x] Duplicate-child prevention after recovery
- [x] Fenced durable coordination mutation
- [x] Current-policy/config revalidation
- [x] Durable cancellation and terminal reconciliation

### Slice 5 - Security review, migration, and release hardening

- [x] Threat-model/security-invariant review
- [x] ADRs for authority, budgets, lineage, and lifecycle
- [x] v0.28.0 to v0.29.0 migration guidance
- [x] Named multi-agent release gate
- [x] Offline wheel/sdist validation
- [x] Release notes and package version 0.29.0
- [ ] Tag, artifacts, and checksums

## Acceptance

RFC-0029 may be accepted for Phoenix OS v0.29.0 only when every Slice plan item
is complete and the full repository quality gate passes.

Acceptance requires evidence that delegation cannot increase authority or root
budgets, recursion/fan-out are bounded, cancellation owns child lifecycle,
durable recovery cannot duplicate children, child results remain untrusted, and
omitting coordination preserves Phoenix OS v0.28.0 behavior.
