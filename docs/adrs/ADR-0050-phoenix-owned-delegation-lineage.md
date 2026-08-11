# ADR-0050: Phoenix-owned delegation lineage and stable child identity

- **Status:** Accepted
- **Date:** 2026-08-11
- **Related:** RFC-0029

## Context

Nested delegation needs enough ancestry to enforce depth, detect cycles, bind child
results, and recover after restart. If a model can fabricate lineage or if recovery
allocates a new child identity for an existing delegation, the system can bypass
depth/cycle controls or silently duplicate work.

## Decision

Delegation lineage is immutable Phoenix-owned typed data. It contains the stable
root run, ordered agent/run ancestry, and the exact delegation edge that introduced
each child. Models and child output cannot manufacture trusted lineage entries.

Each `DelegationId` is permanently bound to at most one Phoenix-owned child
`AgentRunId`. Durable storage commits that binding before child execution can begin.
Recovery reuses the persisted child identity; it never allocates a replacement
child for the same `DelegationId`.

Depth is finite, nested delegation requires explicit current registry policy, and
cycles fail closed. Child results are accepted only when their delegation identity,
child agent identity, and child run identity match the trusted binding. Cross-run
result substitution is rejected.

## Consequences

- A stable lineage can be inspected without storing prompts or child results.
- Duplicate-child prevention survives process restart.
- Nested delegation remains bounded and cycle-safe.
- Historical lineage does not grant current registry or policy authority.

## Alternatives considered

- **Accept model-provided ancestry.** Rejected because untrusted output cannot define
  a security boundary.
- **Generate a fresh child run on recovery.** Rejected because it can duplicate
  already-started work.
- **Identify children only by agent name.** Rejected because results and recovery
  require exact run identity.

## Supersession criteria

A replacement must preserve trusted immutable lineage, finite depth, cycle
prevention, stable delegation-to-child binding, and exact result identity checks.
