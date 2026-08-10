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

The exact initial action is:

```text
agent.delegate
```

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

## Child results

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

## Slice plan

### Slice 0 - RFC foundation and executable specification

- [x] Draft RFC-0029 with explicit security invariants
- [x] Add RFC structure and regression tests
- [x] Establish exact action/resource naming
- [x] Confirm compatibility-by-omission contract

### Slice 1 - Contracts, registry, and authorization

- [ ] Immutable delegation contracts
- [ ] Bounded identifiers, statuses, lineage, limits, and budgets
- [ ] Server-owned child-agent registry
- [ ] Exact `agent.delegate` authorization boundary
- [ ] Deterministic contract and authorization tests

### Slice 2 - Coordinator and bounded lifecycle

- [ ] Delegation coordinator
- [ ] Child admission and lifecycle state machine
- [ ] Depth, fan-out, concurrency, queue, deadline, and budget enforcement
- [ ] Cycle prevention and duplicate-identity rejection
- [ ] Deterministic race and limit tests

### Slice 3 - Results, cancellation, and Runtime ownership

- [ ] Bounded child input/result validation
- [ ] Deterministic aggregation boundary
- [ ] Parent cancellation propagation
- [ ] Controlled shutdown and finite draining
- [ ] RuntimeAssembler opt-in composition
- [ ] Content-free observer and administration

### Slice 4 - Durable coordination and recovery

- [ ] Durable parent/child linkage
- [ ] Stable child identity across restart
- [ ] Duplicate-child prevention after recovery
- [ ] Fenced durable coordination mutation
- [ ] Current-policy/config revalidation
- [ ] Durable cancellation and terminal reconciliation

### Slice 5 - Security review, migration, and release hardening

- [ ] Threat-model/security-invariant review
- [ ] ADRs for authority, budgets, lineage, and lifecycle
- [ ] v0.28.0 to v0.29.0 migration guidance
- [ ] Named multi-agent release gate
- [ ] Offline wheel/sdist validation
- [ ] Release notes and package version 0.29.0
- [ ] Tag, artifacts, and checksums

## Acceptance

RFC-0029 may be accepted for Phoenix OS v0.29.0 only when every Slice plan item
is complete and the full repository quality gate passes.

Acceptance requires evidence that delegation cannot increase authority or root
budgets, recursion/fan-out are bounded, cancellation owns child lifecycle,
durable recovery cannot duplicate children, child results remain untrusted, and
omitting coordination preserves Phoenix OS v0.28.0 behavior.
