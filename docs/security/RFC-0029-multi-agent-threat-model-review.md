# RFC-0029 multi-agent threat-model and security-invariant review

- **Reviewed:** 2026-08-11
- **Release candidate:** Phoenix OS v0.29.0
- **Scope:** registered-agent delegation, authorization, lineage, root budgets,
  child lifecycle, results, cancellation, observability, durable linkage,
  recovery, reconciliation, Runtime composition, migration, and packaging
- **Result:** Accepted for the v0.29.0 multi-agent release gate

## Review method

This review maps the RFC-0029 threat model and all forty-five security invariants
to implementation boundaries and executable regression suites. Parent requests,
model output, child input, child output, persisted delegation metadata, recovery
state, reconciliation evidence, timestamps, identifiers, and storage failures are
treated as untrusted until the relevant Phoenix-owned boundary validates them.

A passing suite does not prove an installed model, tool, storage, policy, secret,
or child-service adapter is benign. Installed adapters remain trusted deployment
code and must be reviewed for the authority explicitly granted to them.

The evidence classes are:

1. immutable delegation contracts, reviewed registration, exact authorization, and
   Phoenix-owned lineage;
2. finite depth/fan-out/concurrency/queue/deadline limits plus monotonic root-budget
   reservation;
3. bounded child execution, cancellation, result binding, deterministic aggregation,
   safe observation, and Runtime ownership;
4. durable delegation identity, restart-safe lifetime accounting, exclusive recovery
   claims, indeterminate-state handling, and explicit reconciliation;
5. migration-by-omission, ADRs, release metadata, packaging inspection, and isolated
   offline package execution.

## Trust boundaries

### Untrusted

- parent-supplied delegation input until strict Phoenix validation;
- all model output, child output, tool output, and aggregation input;
- persisted delegation records and restored databases until decoded and rebound;
- timestamps, status evidence, and reconciliation evidence from external systems;
- historical compatibility or policy metadata when deciding current authority.

### Trusted but least-authority

- current reviewed Phoenix configuration and Runtime composition;
- server-owned delegable-agent registry and compatibility descriptors;
- Phoenix-owned lineage, identifiers, budget ledger, result binding, and state
  transitions;
- current Policy Engine decisions and exact security contexts;
- installed child agent services and durable-store adapters.

RFC-0029 is not a hostile-code sandbox. Trusted adapters receive only the reviewed
inputs and dependencies required by their interface.

## Threat review

| Threat | Required control | Evidence |
| --- | --- | --- |
| Parent transfers its permission, approval, credential, model, or tool authority | Fresh exact `agent.delegate`; independent child admission; no copied security authority | `test_agent_coordination_authorization.py`, `test_agent_coordination_runtime.py` |
| Model constructs an arbitrary executable child | Closed server-owned delegable-agent registry | `test_agent_coordination_registry.py`, `test_agent_coordination_authorization.py` |
| Delegation bypasses exact run/model/tool boundaries | Separate `agent.delegate`; child retains RFC-0026/RFC-0027 authorization | `test_agent_coordination_authorization.py`, `test_agent_coordination_operations.py` |
| Nested delegation escapes depth or creates a cycle | Phoenix-owned lineage, finite depth, explicit nested policy, cycle rejection | `test_agent_coordination_contracts.py`, `test_agent_coordination.py` |
| Fan-out or concurrency forms an unbounded swarm | Finite fan-out, total-child, concurrency, queue, and deadline limits | `test_agent_coordination.py`, `test_agent_coordination_state.py` |
| Child reservations multiply the root budget | Monotonic root reservation; completion does not restore lifetime allowance | `test_agent_coordination.py`, `test_agent_coordination_durable_store.py` |
| Restart restores spent budget or child capacity | Durable lifetime accounting includes terminal records | `test_agent_coordination_durable_store.py` |
| Same delegation creates two child runs | Stable `DelegationId` to one child-run binding committed before execution | `test_agent_coordination_durable_recovery.py`, `test_agent_coordination_durable_store.py` |
| Concurrent recoverers both resume a child | Optimistic compare-and-swap recovery claim | `test_agent_coordination_durable_recovery.py` |
| Process loss repeats an unknown running child | `RUNNING` becomes `INDETERMINATE`; no automatic replay | `test_agent_coordination_durable_recovery.py` |
| Stale child configuration is restored as authority | Current registry compatibility and current policy win | `test_agent_coordination_durable_recovery.py`, `test_agent_coordination_authorization.py` |
| Cross-run child result substitution | Exact delegation/child-agent/child-run binding | `test_agent_coordination_results.py` |
| Child result injection becomes executable authority | Child output remains bounded untrusted data | `test_agent_coordination_results.py`, `test_agent_coordination_runtime.py` |
| Aggregation becomes nondeterministic or unbounded | Canonical deterministic ordering and byte/depth/count limits | `test_agent_coordination_results.py` |
| Parent cancellation leaves detached work | Runtime-owned token from queue to running; propagation; no detached children v1 | `test_agent_coordination_runtime.py`, `test_agent_coordination_operations.py` |
| Shutdown admits new child work or hangs forever | Admission closes first; finite drain/cancel grace | `test_agent_coordination_runtime.py`, `test_agent_coordination_operations.py` |
| Logs, audit, events, or administration leak content | Fixed content-free projections and safe error codes | `test_agent_coordination_operations.py` |
| Upgrade changes v0.28 behavior without opt-in | Coordination composition is absent by omission | `test_agent_coordination_runtime.py`, `test_multi_agent_migration_guidance.py` |
| Package omits coordination code or ships unsafe content | Named gate validates wheel/sdist, paths, metadata, rebuild, and isolated install | `test_multi_agent_release_gate.py` |

## Security-invariant review

### Invariants 1-8: opt-in coordination and exact delegation authority

**Result: satisfied.** Coordination is disabled unless explicitly composed, enabling
it grants no authority by itself, child identity is independent, registration is
server-owned, and `agent.delegate` is a fresh exact action distinct from run, model,
tool, resume, and reconciliation authority.

Evidence: `test_agent_coordination_contracts.py`,
`test_agent_coordination_registry.py`, and
`test_agent_coordination_authorization.py`.

### Invariants 9-15: no authority transfer and current-state child admission

**Result: satisfied.** Policy, permissions, approvals, and credentials are not copied
from parent to child. Each child is admitted from current reviewed configuration and
policy, and removed or changed child compatibility fails closed.

Evidence: `test_agent_coordination_authorization.py`,
`test_agent_coordination_runtime.py`, and
`test_agent_coordination_durable_recovery.py`.

### Invariants 16-24: bounded recursion, swarm limits, deadlines, and root budgets

**Result: satisfied.** Depth, per-parent fan-out, total children, concurrency, queue,
deadline, and child duration are finite. Delegation reservations are derived from
remaining root allowance and never increase the root budget. Unused concurrency is
not confused with restored lifetime budget.

Evidence: `test_agent_coordination.py`, `test_agent_coordination_state.py`, and
`test_agent_coordination_durable_store.py`.

### Invariants 25-31: trusted lineage, cycles, stable child identity, and recovery

**Result: satisfied.** Lineage is Phoenix-owned, cycles fail closed, nested work
requires remaining depth and current policy, one `DelegationId` binds to one child
run, durable recovery never silently creates a replacement child, linkage is
persisted before execution, and result substitution is rejected.

Evidence: `test_agent_coordination_contracts.py`,
`test_agent_coordination_durable_store.py`,
`test_agent_coordination_durable_recovery.py`, and
`test_agent_coordination_results.py`.

### Invariants 32-35: untrusted results and deterministic bounded aggregation

**Result: satisfied.** Child output remains untrusted, size/depth/count bounds are
strict, aggregation is deterministic, and terminal child state is immutable.

Evidence: `test_agent_coordination_results.py`,
`test_agent_coordination_state.py`, and `test_agent_coordination_runtime.py`.

### Invariants 36-39: cancellation, finite shutdown, and no detached children

**Result: satisfied.** Parent cancellation blocks new children, propagates to owned
work, shutdown is finite, and RFC-0029 v1 has no detached child lifecycle.

Evidence: `test_agent_coordination_runtime.py` and
`test_agent_coordination_operations.py`.

### Invariants 40-44: content-free operations and no ambient machine authority

**Result: satisfied.** Coordination emits fixed Phoenix-owned operational facts,
safe surfaces exclude prompts/results/credentials/approvals/secrets/provider
objects/raw exceptions, provider SDK orchestration objects are not public
contracts, and delegation grants no generic shell, filesystem, network, browser,
desktop, or operating-system authority.

Evidence: `test_agent_coordination_operations.py`,
`test_agent_coordination_results.py`, and `test_agent_coordination_runtime.py`.

### Invariant 45: v0.28 compatibility

**Result: satisfied.** When coordination configuration is omitted, Phoenix preserves
v0.28 behavior. Upgrade alone creates no child, delegation store, worker, permission,
approval, credential, tool call, model call, or external access.

Evidence: `test_agent_coordination_runtime.py`,
`test_agent_coordination_durable_composition.py`, and
`test_multi_agent_migration_guidance.py`.

## Residual risks

- A malicious or defective installed child agent, model, tool, storage, policy, or
  secret adapter can abuse authority explicitly granted to that adapter. Process
  isolation and external-system permissions remain deployment responsibilities.
- A child may have completed an external side effect before process loss while
  Phoenix only knows that the child was running. The delegation remains
  indeterminate until reviewed evidence resolves it; exactly-once execution is not
  promised.
- Stable delegation, parent, root, child, counts, durations, and approved digests
  are content-free but may reveal operational traffic patterns.
- Restoring an old durable coordination database can reintroduce historical records.
  Current registry, policy, budgets, compatibility, and reconciliation must still
  win before any work continues.
- The dedicated SQLite reference store is a local reference implementation, not a
  distributed consensus system.
- Future detached children, autonomous scheduling, distributed coordination,
  dynamic child code, or authority transfer require a separate RFC and security
  review rather than inheriting this acceptance.

## Release conclusion

The RFC-0029 threat-model and all forty-five security invariants are accepted for
the Phoenix OS v0.29.0 multi-agent release gate.

This review does not by itself publish v0.29.0. Final publication still requires the
full project quality gate, the named multi-agent release gate, all earlier named
release gates, wheel and sdist inspection, isolated offline package execution, the
release commit, tag, artifacts, and checksums.
